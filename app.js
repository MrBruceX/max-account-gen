import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { pool } from './db.js';
import {
  hashSessionToken, hashLicenseToken, safeEqual, required,
  newOpaqueToken, newCsrfToken, hashPassword, verifyPassword, newLicenseToken
} from './security.js';
import {
  emailSchema, passwordSchema, discordIdSchema, stockAddSchema,
  generateSchema, licenseCreateSchema, bugSchema
} from './validation.js';

const app = express();
const COOKIE = process.env.COOKIE_SECURE === 'false' ? 'ms_session_dev' : '__Host-ms_session';
const SESSION_MS = 12 * 60 * 60 * 1000;
const TIER_DAILY_LIMIT = { weekly: 10, monthly: 15, lifetime: 25 };
const validOrigin = process.env.PUBLIC_ORIGIN;
if (process.env.NODE_ENV === 'production') {
  required('SESSION_PEPPER');
  required('TOKEN_PEPPER');
  if (!validOrigin) throw new Error('PUBLIC_ORIGIN is required in production');
  const parsedOrigin = new URL(validOrigin);
  if (parsedOrigin.protocol !== 'https:' || parsedOrigin.origin !== validOrigin) {
    throw new Error('PUBLIC_ORIGIN must be an exact HTTPS origin, without a path');
  }
  if (process.env.COOKIE_SECURE === 'false') throw new Error('COOKIE_SECURE=false is forbidden in production');
}

app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https://cdn.discordapp.com'],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'no-referrer' }
}));
app.use(express.json({ limit: '32kb', strict: true }));
app.use('/api', (_req,res,next)=>{res.set('Cache-Control','no-store');next();});
app.use((req, res, next) => {
  if (validOrigin && req.headers.origin && req.headers.origin !== validOrigin) {
    return res.status(403).json({ error: 'origin_not_allowed' });
  }
  next();
});

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false });
const bootstrapLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 3, standardHeaders: 'draft-7', legacyHeaders: false });
const actionLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: 'draft-7', legacyHeaders: false });

function cookieOptions() {
  return { httpOnly: true, secure: process.env.COOKIE_SECURE !== 'false', sameSite: 'strict', path: '/', maxAge: SESSION_MS };
}
function fail(res, status, error) { return res.status(status).json({ error }); }
function validate(schema, data) {
  const parsed = schema.safeParse(data);
  return parsed.success ? parsed.data : null;
}
async function audit(actorType, actorId, action, metadata = {}) {
  await pool.query(
    'INSERT INTO audit_log(actor_type,actor_id,action,metadata) VALUES($1,$2,$3,$4)',
    [actorType, actorId ?? null, action, JSON.stringify(metadata)]
  );
}
async function createSession(res, userType, actorId, licenseId = null) {
  const raw = newOpaqueToken();
  const csrf = newCsrfToken();
  const expires = new Date(Date.now() + SESSION_MS);
  await pool.query(
    `INSERT INTO sessions(token_hash,csrf_token,user_type,admin_id,license_id,expires_at)
     VALUES($1,$2,$3,$4,$5,$6)`,
    [hashSessionToken(raw), csrf, userType, userType === 'admin' ? actorId : null,
      userType === 'customer' ? licenseId : null, expires]
  );
  res.cookie(COOKIE, raw, cookieOptions());
  return csrf;
}
async function auth(req, res, next) {
  try {
    const raw = req.cookies?.[COOKIE];
    if (!raw) return fail(res, 401, 'authentication_required');
    const q = await pool.query(
      `SELECT s.id,s.user_type,s.admin_id,s.license_id,s.csrf_token,s.expires_at,
              l.tier,l.discord_id,l.rockstar_code_access,l.expires_at AS license_expires,l.revoked_at
       FROM sessions s LEFT JOIN licenses l ON l.id=s.license_id
       WHERE s.token_hash=$1 AND s.expires_at>now()`,
      [hashSessionToken(raw)]
    );
    if (!q.rowCount) return fail(res, 401, 'session_expired');
    const row = q.rows[0];
    if (row.user_type === 'customer' && (row.revoked_at || new Date(row.license_expires) <= new Date())) {
      await pool.query('DELETE FROM sessions WHERE id=$1', [row.id]);
      res.clearCookie(COOKIE, { path: '/', secure: process.env.COOKIE_SECURE !== 'false', sameSite: 'strict' });
      return fail(res, 401, 'license_inactive');
    }
    req.auth = row;
    next();
  } catch (e) { next(e); }
}
function requireAdmin(req, res, next) {
  if (req.auth?.user_type !== 'admin') return fail(res, 403, 'admin_required');
  next();
}
function requireCustomer(req, res, next) {
  if (req.auth?.user_type !== 'customer') return fail(res, 403, 'customer_required');
  next();
}
function csrf(req, res, next) {
  const origin = req.headers.origin;
  if (validOrigin && origin !== validOrigin) return fail(res, 403, 'origin_not_allowed');
  if (!safeEqual(req.headers['x-csrf-token'], req.auth?.csrf_token)) return fail(res, 403, 'csrf_failed');
  next();
}
app.use((req, res, next) => {
  // Cookie parsing is intentionally tiny and does not trust arbitrary cookie values.
  const raw = req.headers.cookie || '';
  req.cookies = Object.fromEntries(raw.split(';').map(x => x.trim()).filter(Boolean).map(x => {
    const i = x.indexOf('=');
    return i < 0 ? [x, ''] : [x.slice(0, i), decodeURIComponent(x.slice(i + 1))];
  }));
  next();
});
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true }); }
  catch { fail(res, 503, 'database_unavailable'); }
});

// First owner is created out-of-band with the terminal bootstrap command.

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const email = validate(emailSchema, req.body?.email);
    const password = typeof req.body?.password === 'string' ? req.body.password.slice(0,128) : '';
    if (!email || !password) return fail(res, 400, 'invalid_credentials');
    const q = await pool.query('SELECT id,email,password_hash FROM admins WHERE lower(email)=lower($1)', [email]);
    const row = q.rows[0];
    if (!row || !(await verifyPassword(row.password_hash, password))) return fail(res, 401, 'invalid_credentials');
    const csrfToken = await createSession(res, 'admin', row.id);
    await audit('admin', row.id, 'login');
    res.json({ user: { id: row.id, email: row.email }, csrfToken });
  } catch (e) { next(e); }
});

app.get('/api/auth/session', auth, (req, res) => {
  res.json({
    user: req.auth.user_type === 'admin'
      ? { type: 'admin', id: req.auth.admin_id }
      : { type: 'customer', discordId: req.auth.discord_id, tier: req.auth.tier, expiresAt: req.auth.license_expires },
    csrfToken: req.auth.csrf_token
  });
});
app.post('/api/auth/logout', auth, csrf, async (req, res, next) => {
  try {
    await pool.query('DELETE FROM sessions WHERE id=$1', [req.auth.id]);
    res.clearCookie(COOKIE, { path: '/', secure: process.env.COOKIE_SECURE !== 'false', sameSite: 'strict' });
    res.status(204).end();
  } catch (e) { next(e); }
});

// Public license activation: token is HMAC-hashed server-side and Discord binding is one-time.
app.post('/api/customer/activate', loginLimiter, async (req, res, next) => {
  try {
    const token = typeof req.body?.token === 'string' ? req.body.token.slice(0,128) : '';
    const discordId = validate(discordIdSchema, req.body?.discordId);
    if (!token || !discordId) return fail(res, 400, 'invalid_input');
    const q = await pool.query(
      `SELECT id,tier,expires_at,discord_id FROM licenses
       WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now()`,
      [hashLicenseToken(token)]
    );
    const lic = q.rows[0];
    if (!lic) return fail(res, 401, 'license_invalid');
    if (lic.discord_id && lic.discord_id !== discordId) return fail(res, 403, 'discord_mismatch');
    const upd = await pool.query(
      `UPDATE licenses SET discord_id=COALESCE(discord_id,$2)
       WHERE id=$1 AND (discord_id IS NULL OR discord_id=$2) RETURNING id`,
      [lic.id, discordId]
    );
    if (!upd.rowCount) return fail(res, 409, 'activation_conflict');
    const csrfToken = await createSession(res, 'customer', null, lic.id);
    await audit('customer', lic.id, 'activate', { discordId });
    res.json({ user: { type: 'customer', discordId, tier: lic.tier, expiresAt: lic.expires_at }, csrfToken });
  } catch (e) { next(e); }
});

app.get('/api/public/summary', async (_req, res, next) => {
  try {
    const [counts, settings] = await Promise.all([
      pool.query('SELECT type, count(*)::int AS count FROM stock_items GROUP BY type'),
      pool.query("SELECT key,value FROM settings WHERE key IN ('announcement','stock_update')")
    ]);
    const stock = Object.fromEntries(['discord','steam','rockstar','rockstar_code'].map(t => [t, 0]));
    for (const row of counts.rows) stock[row.type] = row.count;
    const values = Object.fromEntries(settings.rows.map(r => [r.key, r.value]));
    res.json({ stock, announcement: values.announcement || '', stockUpdate: values.stock_update || '' });
  } catch (e) { next(e); }
});

// Server-side generation is atomic: stock and quota are checked and consumed in one transaction.
app.post('/api/generate', actionLimiter, auth, requireCustomer, csrf, async (req, res, next) => {
  const input = validate(generateSchema, req.body);
  if (!input) return fail(res, 400, 'invalid_input');
  if (input.type === 'rockstar_code' && !req.auth.rockstar_code_access) return fail(res, 403, 'service_not_allowed');
  const limit = TIER_DAILY_LIMIT[req.auth.tier];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const usage = await client.query(
      `INSERT INTO daily_usage(license_id,usage_date,used) VALUES($1,CURRENT_DATE,0)
       ON CONFLICT(license_id,usage_date) DO UPDATE SET used=daily_usage.used
       RETURNING used`,
      [req.auth.license_id]
    );
    if (usage.rows[0].used + input.count > limit) {
      await client.query('ROLLBACK');
      return fail(res, 429, 'daily_limit_reached');
    }
    const picked = await client.query(
      `SELECT id FROM stock_items WHERE type=$1 ORDER BY id
       LIMIT $2 FOR UPDATE SKIP LOCKED`,
      [input.type, input.count]
    );
    if (picked.rowCount < input.count) {
      await client.query('ROLLBACK');
      return fail(res, 409, 'out_of_stock');
    }
    const ids = picked.rows.map(r => r.id);
    const removed = await client.query('DELETE FROM stock_items WHERE id=ANY($1::bigint[]) RETURNING secret', [ids]);
    if (removed.rowCount !== input.count) {
      await client.query('ROLLBACK');
      return fail(res, 409, 'stock_changed_retry');
    }
    const used = await client.query(
      `UPDATE daily_usage SET used=used+$3
       WHERE license_id=$1 AND usage_date=CURRENT_DATE AND used+$3<=$2 RETURNING used`,
      [req.auth.license_id, limit, input.count]
    );
    if (!used.rowCount) {
      await client.query('ROLLBACK');
      return fail(res, 429, 'daily_limit_reached');
    }
    await client.query('COMMIT');
    res.json({ items: removed.rows.map(r => r.secret), remaining: limit - used.rows[0].used });
  } catch (e) {
    await client.query('ROLLBACK');
    next(e);
  } finally { client.release(); }
});

// Admin inventory management.
app.get('/api/admin/stock', auth, requireAdmin, async (_req, res, next) => {
  try {
    const q = await pool.query('SELECT type,count(*)::int AS count FROM stock_items GROUP BY type');
    const stock = Object.fromEntries(['discord','steam','rockstar','rockstar_code'].map(t => [t,0]));
    for (const row of q.rows) stock[row.type] = row.count;
    res.json({ stock });
  } catch (e) { next(e); }
});
app.post('/api/admin/stock', auth, requireAdmin, csrf, async (req, res, next) => {
  const data = validate(stockAddSchema, req.body);
  if (!data) return fail(res, 400, 'invalid_input');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const line of data.lines) await client.query('INSERT INTO stock_items(type,secret) VALUES($1,$2)', [data.type,line]);
    await client.query('COMMIT');
    await audit('admin', req.auth.admin_id, 'stock_add', { type:data.type, count:data.lines.length });
    res.status(201).json({ added: data.lines.length });
  } catch (e) { await client.query('ROLLBACK'); next(e); }
  finally { client.release(); }
});
app.delete('/api/admin/stock/:type', auth, requireAdmin, csrf, async (req, res, next) => {
  if (!['discord','steam','rockstar','rockstar_code'].includes(req.params.type)) return fail(res,400,'invalid_type');
  try {
    const q = await pool.query('DELETE FROM stock_items WHERE type=$1', [req.params.type]);
    await audit('admin', req.auth.admin_id, 'stock_clear', { type:req.params.type, count:q.rowCount });
    res.json({ deleted:q.rowCount });
  } catch (e) { next(e); }
});

// License issuance returns the raw token exactly once. Only its HMAC is persisted.
app.post('/api/admin/licenses', auth, requireAdmin, csrf, async (req, res, next) => {
  const data = validate(licenseCreateSchema, req.body);
  if (!data) return fail(res,400,'invalid_input');
  try {
    const raw = newLicenseToken();
    const expires = new Date(Date.now() + data.days * 86400000);
    const q = await pool.query(
      `INSERT INTO licenses(token_hash,label,tier,expires_at,discord_id,rockstar_code_access)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING id,tier,expires_at`,
      [hashLicenseToken(raw),data.label,data.tier,expires,data.discordId || null,data.rockstarCodeAccess]
    );
    await audit('admin',req.auth.admin_id,'license_create',{ licenseId:q.rows[0].id,tier:data.tier });
    res.status(201).json({ license:{id:q.rows[0].id,tier:q.rows[0].tier,expiresAt:q.rows[0].expires_at}, token:raw });
  } catch (e) { next(e); }
});
app.get('/api/admin/licenses', auth, requireAdmin, async (_req,res,next) => {
  try {
    const q = await pool.query(
      `SELECT id,label,tier,expires_at,discord_id,rockstar_code_access,revoked_at,created_at
       FROM licenses ORDER BY id DESC LIMIT 500`
    );
    res.json({ licenses:q.rows });
  } catch(e) { next(e); }
});
app.post('/api/admin/licenses/:id/revoke', auth, requireAdmin, csrf, async (req,res,next) => {
  if (!/^[0-9]{1,18}$/.test(req.params.id)) return fail(res,400,'invalid_id');
  try {
    const q = await pool.query('UPDATE licenses SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL RETURNING id',[req.params.id]);
    await pool.query('DELETE FROM sessions WHERE license_id=$1',[req.params.id]);
    await audit('admin',req.auth.admin_id,'license_revoke',{licenseId:req.params.id});
    res.json({ revoked:!!q.rowCount });
  } catch(e) { next(e); }
});

app.get('/api/admin/settings',auth,requireAdmin,async(_req,res,next)=>{try{const q=await pool.query("SELECT key,value FROM settings WHERE key IN ('announcement','stock_update')");res.json({settings:Object.fromEntries(q.rows.map(r=>[r.key,r.value]))});}catch(e){next(e);}});
app.put('/api/admin/settings/:key',auth,requireAdmin,csrf,async(req,res,next)=>{const key=req.params.key;if(!['announcement','stock_update'].includes(key))return fail(res,400,'invalid_setting');if(typeof req.body?.value!=='string'||req.body.value.length>500)return fail(res,400,'invalid_value');try{if(req.body.value.trim())await pool.query("INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()",[key,req.body.value.trim()]);else await pool.query('DELETE FROM settings WHERE key=$1',[key]);await audit('admin',req.auth.admin_id,'setting_update',{key});res.json({ok:true});}catch(e){next(e);}});
// Public bug intake; admin review is protected.
app.post('/api/bug-reports', actionLimiter, async (req,res,next) => {
  const data = validate(bugSchema, req.body);
  if (!data) return fail(res,400,'invalid_input');
  try {
    const q = await pool.query(
      `INSERT INTO bug_reports(discord_id,username,category,title,body)
       VALUES($1,$2,$3,$4,$5) RETURNING id,created_at`,
      [data.discordId,data.username,data.category,data.title,data.body]
    );
    res.status(201).json(q.rows[0]);
  } catch(e) { next(e); }
});
app.get('/api/admin/bug-reports', auth, requireAdmin, async (_req,res,next) => {
  try {
    const q = await pool.query('SELECT id,discord_id,username,category,title,body,status,created_at FROM bug_reports ORDER BY id DESC LIMIT 500');
    res.json({ reports:q.rows });
  } catch(e) { next(e); }
});
app.patch('/api/admin/bug-reports/:id', auth, requireAdmin, csrf, async (req,res,next) => {
  if (!/^[0-9]{1,18}$/.test(req.params.id)) return fail(res,400,'invalid_id');
  const status = ['open','in_progress','resolved'].includes(req.body?.status) ? req.body.status : null;
  if (!status) return fail(res,400,'invalid_status');
  try {
    const q = await pool.query('UPDATE bug_reports SET status=$2 WHERE id=$1 RETURNING id,status',[req.params.id,status]);
    if (!q.rowCount) return fail(res,404,'not_found');
    res.json(q.rows[0]);
  } catch(e) { next(e); }
});

const publicDir=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../public');
app.use(express.static(publicDir,{dotfiles:'deny',index:'index.html',etag:true,maxAge:'1h'}));
app.get('/',(_req,res)=>res.sendFile(path.join(publicDir,'index.html')));
app.use((err,_req,res,_next)=>{
  console.error('API error:', err?.message || 'unknown');
  if (res.headersSent) return;
  res.status(500).json({ error:'internal_error' });
});

export default app;
