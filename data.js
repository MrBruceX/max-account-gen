// data.js — MAX SHOP · hardened build v3
// CHANGES FROM v2:
//   • setOwnerSecret REMOVED from public interface — owner bootstrap done via
//     MS._bootstrap(secret) which is stripped from the frozen return object.
//     Only accessible via the dedicated owner-setup page before first login.
//   • ms_stock_update / ms_announcement now use _INST-salted keys (were hardcoded).
//   • _verify: empty integrity on a non-empty key array now triggers wipe (was
//     returning false → wipe on clean install race).
//   • addStock: deduplication — exact-match lines already in stock are skipped.
//   • generateKey / getTokens_all removed from public interface.
//   • setOwnerSecret call-rate limited: max 3 attempts per 15 min session window.
//   • Raw generated key surface: addKey now returns the raw key once on creation
//     so the admin UI can present it; it is never stored or re-surfaced after that.
//   • Owner bootstrap flag: once owner secret is set, _OWN_READY key is written;
//     pages can check MS.ownerReady (sync, bool) to gate bootstrap UI.

const MS = (() => {
  'use strict';

  // ── Per-install salt ────────────────────────────────────────────────────────
  const _INST = (() => {
    const k = '__ms_inst__';
    let v = localStorage.getItem(k);
    if (!v) {
      v = Array.from(crypto.getRandomValues(new Uint8Array(12)))
              .map(b => b.toString(16).padStart(2, '0')).join('');
      localStorage.setItem(k, v);
    }
    return v;
  })();

  // ── HMAC engine ─────────────────────────────────────────────────────────────
  // Per-install derivation; client-side derivation is not a true server secret.
  const _PEPPER_SEED = 'max-shop-pepper-v3:' + _INST;
  let _pepperKeyCache = null;
  async function _pepperKey() {
    if (_pepperKeyCache) return _pepperKeyCache;
    const enc = new TextEncoder();
    _pepperKeyCache = await crypto.subtle.importKey(
      'raw', enc.encode(_PEPPER_SEED),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    return _pepperKeyCache;
  }
  async function _hmac(msg) {
    const enc = new TextEncoder();
    const key = await _pepperKey();
    const sig  = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
    return Array.from(new Uint8Array(sig))
                .map(b => b.toString(16).padStart(2, '0')).join('')
                .slice(0, 32);
  }

  // ── Owner secret management ─────────────────────────────────────────────────
  const _OWN_K     = btoa('ms_own_'   + _INST).replace(/=/g, '');
  const _OWN_READY = btoa('ms_ownrdy_'+ _INST).replace(/=/g, '');

  // Rate-limit for bootstrap: 3 attempts per 15 min
  const _OWN_RL_CNT = btoa('ms_ownrl_c' + _INST).replace(/=/g, '');
  const _OWN_RL_TS  = btoa('ms_ownrl_t' + _INST).replace(/=/g, '');
  const _OWN_RL_WIN = 900000; // 15 min
  const _OWN_RL_MAX = 3;

  function _ownerRLCheck() {
    const now   = Date.now();
    const since = parseInt(sessionStorage.getItem(_OWN_RL_TS) || '0');
    let   cnt   = parseInt(sessionStorage.getItem(_OWN_RL_CNT) || '0');
    if (now - since > _OWN_RL_WIN) { cnt = 0; sessionStorage.setItem(_OWN_RL_TS, String(now)); }
    if (cnt >= _OWN_RL_MAX) return false;
    sessionStorage.setItem(_OWN_RL_CNT, String(cnt + 1));
    return true;
  }

  // Internal only — not on frozen public interface
  async function _setOwnerSecret(secret) {
    if (localStorage.getItem(_OWN_READY) === '1' || localStorage.getItem(_OWN_K)) return { ok: false, reason: 'already_set' };
    if (!secret || secret.length < 8 || secret.length > 128) return { ok: false, reason: 'length' };
    if (!_ownerRLCheck()) return { ok: false, reason: 'rate_limited' };
    const sig = await _hmac(secret + _INST);
    localStorage.setItem(_OWN_K,     sig);
    localStorage.setItem(_OWN_READY, '1');
    return { ok: true };
  }

  async function _isOwnerKey(key) {
    const stored = localStorage.getItem(_OWN_K);
    if (!stored) return false;
    return (await _hmac(key + _INST)) === stored;
  }

  const ownerReady = !!localStorage.getItem(_OWN_READY);

  // ── Salted storage key names ─────────────────────────────────────────────────
  const _S = {
    stock  : t  => btoa('ms_s_'         + t + _INST).replace(/=/g, ''),
    keys   : () => btoa('ms_k'          + _INST).replace(/=/g, ''),
    int    : () => btoa('ms_integrity'  + _INST).replace(/=/g, ''),
    daily  : d  => btoa('ms_d_'         + d + _INST).replace(/=/g, ''),
    hist   : () => btoa('ms_h2'         + _INST).replace(/=/g, ''),
    hdate  : () => btoa('ms_hd'         + _INST).replace(/=/g, ''),
    tokens : () => btoa('ms_tokens'     + _INST).replace(/=/g, ''),
    bugs   : () => btoa('ms_bugs'       + _INST).replace(/=/g, ''),
    chat   : () => btoa('ms_chat'       + _INST).replace(/=/g, ''),
    sess   : () => btoa('ms_ss'         + _INST).replace(/=/g, ''),
    // FIX: announcements and stock updates salted — were hardcoded, bypassed _INST
    ann    : () => btoa('ms_ann'        + _INST).replace(/=/g, ''),
    su     : () => btoa('ms_su'         + _INST).replace(/=/g, ''),
    failCnt: () => btoa('ms_fc'         + _INST).replace(/=/g, ''),
    failTs : () => btoa('ms_ft'         + _INST).replace(/=/g, ''),
  };

  // ── Integrity seal ───────────────────────────────────────────────────────────
  async function _seal(keys) {
    const hash = await _hmac(JSON.stringify(keys) + _INST);
    localStorage.setItem(_S.int(), hash);
  }
  async function _verify(keys) {
    const stored = localStorage.getItem(_S.int());
    // FIX: empty integrity on non-empty key array → tampered, wipe.
    // Previously returned false here which triggered wipe on clean install too —
    // fixed by checking array length: empty keys + no seal = clean install, OK.
    if (!stored) return keys.length === 0;
    return stored === await _hmac(JSON.stringify(keys) + _INST);
  }
  function _wipeAndBan() {
    [_S.keys(), _S.int(), _S.tokens(), _S.hist(), _S.hdate(), _S.bugs(),
     _S.chat(), _S.ann(), _S.su(), _S.failCnt(), _S.failTs(),
     ...['discord','steam','rockstar','rockstar_code'].map(t => _S.stock(t))]
      .forEach(k => localStorage.removeItem(k));
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i);
      try {
        const decoded = atob(key);
        if (decoded.startsWith('ms_d_') && decoded.endsWith(_INST)) localStorage.removeItem(key);
      } catch {}
    }
    clearSession();
    clearTokenSession();
    if (!window.location.pathname.includes('index')) window.location.replace('index.html');
  }

  // ── UI lock ──────────────────────────────────────────────────────────────────
  function _lockUI() {
    document.addEventListener('contextmenu', e => e.preventDefault(), true);
    document.addEventListener('selectstart',  e => e.preventDefault(), true);
    document.addEventListener('copy',         e => e.preventDefault(), true);
    document.addEventListener('cut',          e => e.preventDefault(), true);
    document.addEventListener('keydown', e => {
      if (e.key === 'F12' || e.keyCode === 123) { e.preventDefault(); e.stopPropagation(); return; }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey &&
          ['I','J','C','K'].includes(e.key.toUpperCase())) { e.preventDefault(); e.stopPropagation(); return; }
      if (e.metaKey && e.altKey && e.key.toUpperCase() === 'I') { e.preventDefault(); e.stopPropagation(); return; }
      if ((e.ctrlKey || e.metaKey) && ['U','S','P'].includes(e.key.toUpperCase())) { e.preventDefault(); return; }
    }, true);
  }
  document.readyState === 'loading'
    ? document.addEventListener('DOMContentLoaded', _lockUI)
    : _lockUI();

  // ── Stock ────────────────────────────────────────────────────────────────────
  function getStock(type)      { try { return JSON.parse(localStorage.getItem(_S.stock(type)) || '[]'); } catch { return []; } }
  function setStock(type, arr) { localStorage.setItem(_S.stock(type), JSON.stringify(arr)); }
  function addStock(type, lines) {
    const cur    = getStock(type);
    // FIX: deduplicate — skip lines already present
    const curSet = new Set(cur);
    const added  = lines.split('\n')
                        .map(l => l.trim())
                        .filter(l => l && !curSet.has(l))
                        .slice(0, 50000);
    setStock(type, [...cur, ...added]);
    return added.length;
  }
  async function popStock(type, n) {
    if (!Number.isInteger(n) || n < 1) return null;
    if (!navigator.locks || typeof navigator.locks.request !== 'function')
      throw new Error('Safe cross-tab stock locking is unavailable in this browser.');
    return navigator.locks.request('max-shop-stock-' + type, async () => {
      const cur = getStock(type);
      if (cur.length < n) return null;
      const taken = cur.splice(0, n);
      setStock(type, cur);
      return taken;
    });
  }
  function countStock(type) { return getStock(type).length; }

  // ── Keys ─────────────────────────────────────────────────────────────────────
  const TIER_LIMITS = { weekly: 10, monthly: 15, lifetime: 25 };
  const TIER_LABELS = { weekly: 'Weekly', monthly: 'Monthly', lifetime: 'Lifetime' };

  function getKeys() { try { return JSON.parse(localStorage.getItem(_S.keys()) || '[]'); } catch { return []; } }
  async function setKeys(arr) { localStorage.setItem(_S.keys(), JSON.stringify(arr)); await _seal(arr); }

  // FIX: returns raw key on creation (the ONE moment it's accessible) instead of bool
  // Caller must present and discard — it is not stored or re-surfaced.
  async function addKey(key, tier, pcId, discordId, rockstarCodeAccess) {
    if (!key || key.length > 128) return null;
    const keys = getKeys();
    const sig  = await _hmac(key);
    if (keys.find(k => k.sig === sig)) return null; // duplicate
    const t = TIER_LIMITS[tier] ? tier : 'weekly';
    keys.push({
      sig,
      tier: t, label: TIER_LABELS[t],
      pcId: (pcId || '').slice(0, 128),
      discordId: (discordId || '').slice(0, 24),
      created: Date.now(), used: false, uses: 0, lastUsed: 0,
      lockedDiscord: '',
      rockstarCodeAccess: rockstarCodeAccess === true,
      revoked: false,
    });
    await setKeys(keys);
    return key; // raw key returned once — admin UI copies it immediately
  }

  async function setRockstarCodeAccess(sig, enabled) {
    const keys = getKeys();
    const idx  = keys.findIndex(k => k.sig === sig);
    if (idx === -1) return false;
    keys[idx].rockstarCodeAccess = !!enabled;
    await setKeys(keys);
    return true;
  }

  async function revokeKey(sig) {
    const keys = getKeys();
    const idx  = keys.findIndex(k => k.sig === sig);
    if (idx === -1) return false;
    keys[idx].revoked = true;
    await setKeys(keys);
    return true;
  }

  async function _validateRaw(key) {
    if (await _isOwnerKey(key)) return 'owner';
    const keys = getKeys();
    if (keys.length > 0) {
      const ok = await _verify(keys);
      if (!ok) { _wipeAndBan(); return null; }
    }
    const sig   = await _hmac(key);
    const found = keys.find(k => k.sig === sig);
    if (!found || found.revoked) return null;
    return 'user';
  }

  async function lockKeyToDiscord(sig, discordId) {
    const keys = getKeys();
    const idx  = keys.findIndex(k => k.sig === sig);
    if (idx === -1) return { ok: false, reason: 'key_not_found' };
    if (!keys[idx].lockedDiscord) {
      keys[idx].lockedDiscord = discordId;
      await setKeys(keys);
      return { ok: true, firstLock: true };
    }
    if (keys[idx].lockedDiscord !== discordId) return { ok: false, reason: 'discord_mismatch' };
    return { ok: true };
  }

  async function lockKeyToDiscordByKey(key, discordId) {
    const sig = await _hmac(key);
    return lockKeyToDiscord(sig, discordId);
  }

  async function updateKeyBinding(sig, pcId, discordId) {
    const keys = getKeys();
    const idx  = keys.findIndex(k => k.sig === sig);
    if (idx === -1) return false;
    keys[idx].pcId      = (pcId      || '').slice(0, 128);
    keys[idx].discordId = (discordId || '').slice(0, 24);
    await setKeys(keys);
    return true;
  }

  async function resetKeyLock(sig) {
    const keys = getKeys();
    const idx  = keys.findIndex(k => k.sig === sig);
    if (idx === -1) return false;
    keys[idx].lockedDiscord = '';
    await setKeys(keys);
    return true;
  }

  async function deleteKey(sig) {
    await setKeys(getKeys().filter(k => k.sig !== sig));
  }

  async function markKeyUsed(key) {
    const sig  = await _hmac(key);
    const keys = getKeys();
    const idx  = keys.findIndex(k => k.sig === sig);
    if (idx !== -1) {
      keys[idx].used     = true;
      keys[idx].uses     = (keys[idx].uses || 0) + 1;
      keys[idx].lastUsed = Date.now();
      await setKeys(keys);
    }
  }

  // FIX: generateKey is internal only — removed from public interface
  function _generateKey() {
    const seg = () => Array.from(crypto.getRandomValues(new Uint8Array(4)))
                          .map(b => b.toString(36).toUpperCase()).join('').slice(0, 5);
    return `MAX-${seg()}-${seg()}-${seg()}`;
  }

  function getKeyDataBySig(sig) {
    return getKeys().find(k => k.sig === sig) || null;
  }

  async function getKeyData(key) {
    const sig = await _hmac(key);
    return getKeys().find(k => k.sig === sig) || null;
  }

  // ── Fail counter ─────────────────────────────────────────────────────────────
  const _WINDOW = 900000;
  const _MAX    = 5;

  function _recordFail() {
    const now   = Date.now();
    const since = parseInt(sessionStorage.getItem(_S.failTs()) || '0');
    let count   = parseInt(sessionStorage.getItem(_S.failCnt()) || '0');
    if (now - since > _WINDOW) { count = 0; sessionStorage.setItem(_S.failTs(), String(now)); }
    sessionStorage.setItem(_S.failCnt(), String(count + 1));
  }
  function _isLocked() {
    const since = parseInt(sessionStorage.getItem(_S.failTs()) || '0');
    let count   = parseInt(sessionStorage.getItem(_S.failCnt()) || '0');
    if (Date.now() - since > _WINDOW) count = 0;
    return count >= _MAX;
  }
  function _remainingMin() {
    const since = parseInt(sessionStorage.getItem(_S.failTs()) || '0');
    return Math.ceil((_WINDOW - (Date.now() - since)) / 60000);
  }

  async function validateKey(key) {
    if (!key || typeof key !== 'string' || key.length > 128) throw new Error('Invalid key format.');
    if (_isLocked()) throw new Error(`Too many attempts. Try again in ${_remainingMin()} min.`);
    const result = await _validateRaw(key);
    if (!result) _recordFail();
    return result;
  }

  // ── Session ──────────────────────────────────────────────────────────────────
  function _tabId() {
    if (!sessionStorage.getItem('_tid'))
      sessionStorage.setItem('_tid', Array.from(crypto.getRandomValues(new Uint8Array(8)))
                                         .map(b => b.toString(16).padStart(2, '0')).join(''));
    return sessionStorage.getItem('_tid');
  }

  function _sessRawKey() { return btoa('ms_srk_' + _INST + _tabId()).replace(/=/g, ''); }

  async function setSession(key, meta) {
    const tid      = _tabId();
    const proof    = await _hmac(key + tid + _INST);
    const isOwner  = await _isOwnerKey(key);
    const role     = isOwner ? 'owner' : 'user';
    const roleTok  = await _hmac(role + tid + _INST);

    sessionStorage.setItem(_S.sess(),         proof);
    sessionStorage.setItem(_S.sess() + '_r',  roleTok);
    sessionStorage.setItem(_sessRawKey(),      key);
    if (meta) sessionStorage.setItem(_S.sess() + '_m', JSON.stringify(meta));
  }

  async function getSession() {
    const proof = sessionStorage.getItem(_S.sess());
    const rawKey = sessionStorage.getItem(_sessRawKey());
    if (!proof || !rawKey) return null;
    if (proof !== await _hmac(rawKey + _tabId() + _INST)) { clearSession(); return null; }
    return proof;
  }
  function getSessionMeta() {
    try { return JSON.parse(sessionStorage.getItem(_S.sess() + '_m') || 'null'); } catch { return null; }
  }
  function clearSession() {
    [_S.sess(), _S.sess() + '_r', _S.sess() + '_m', _sessRawKey()]
      .forEach(k => sessionStorage.removeItem(k));
  }

  async function isAdmin() {
    if (!(await getSession())) return false;
    const rawKey = sessionStorage.getItem(_sessRawKey());
    if (!rawKey || !(await _isOwnerKey(rawKey))) return false;
    const roleTok = sessionStorage.getItem(_S.sess() + '_r');
    return !!roleTok && roleTok === await _hmac('owner' + _tabId() + _INST);
  }

  // ── Token sessions ───────────────────────────────────────────────────────────
  const _TS = {
    tok  : () => btoa('ms_tsess_tok'  + _INST).replace(/=/g, ''),
    disc : () => btoa('ms_tsess_disc' + _INST).replace(/=/g, ''),
    tier : () => btoa('ms_tsess_tier' + _INST).replace(/=/g, ''),
    exp  : () => btoa('ms_tsess_exp'  + _INST).replace(/=/g, ''),
  };
  function setTokenSession(tok, discordId, tier, expires) {
    sessionStorage.setItem(_TS.tok(),  tok);
    sessionStorage.setItem(_TS.disc(), discordId);
    sessionStorage.setItem(_TS.tier(), tier);
    sessionStorage.setItem(_TS.exp(),  String(expires));
  }
  function getTokenSession() {
    const tok = sessionStorage.getItem(_TS.tok());
    if (!tok) return null;
    const exp = parseInt(sessionStorage.getItem(_TS.exp()) || '0');
    if (Date.now() > exp) { clearTokenSession(); return null; }
    return {
      tok,
      discordId: sessionStorage.getItem(_TS.disc()),
      tier: sessionStorage.getItem(_TS.tier()) || 'weekly',
      expires: exp,
    };
  }
  function clearTokenSession() {
    [_TS.tok(), _TS.disc(), _TS.tier(), _TS.exp()].forEach(k => sessionStorage.removeItem(k));
  }

  // ── Access Tokens ────────────────────────────────────────────────────────────
  function _getTokens() { try { return JSON.parse(localStorage.getItem(_S.tokens()) || '[]'); } catch { return []; } }
  function _setTokens(arr) { localStorage.setItem(_S.tokens(), JSON.stringify(arr)); }
  function _genTok() {
    return Array.from(crypto.getRandomValues(new Uint8Array(24)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function addToken(label, days, discordId, tier) {
    const tokens = _getTokens(), tok = _genTok();
    const tokHash = await _hmac('access-token:' + tok);
    const t = TIER_LIMITS[tier] ? tier : 'weekly';
    tokens.push({ tokHash, label: (label || '').slice(0, 128),
      discordId: /^\d{15,20}$/.test(discordId || '') ? discordId : '',
      tier: t, created: Date.now(), expires: Date.now() + days * 86400000, days,
      lockedDiscord: '', revoked: false });
    _setTokens(tokens);
    return tok;
  }

  async function getToken(tok) {
    const tokens = _getTokens(), tokHash = await _hmac('access-token:' + String(tok || ''));
    let found = tokens.find(t => t.tokHash === tokHash);
    if (!found) {
      const legacy = tokens.find(t => t.tok === tok);
      if (legacy) { delete legacy.tok; legacy.tokHash = tokHash; _setTokens(tokens); found = legacy; }
    }
    return found ? { ...found, tok } : null;
  }
  async function validateToken(tok) {
    const found = await getToken(tok);
    if (!found) return { ok: false, reason: 'not_found' };
    if (found.revoked) return { ok: false, reason: 'revoked' };
    if (Date.now() > found.expires) return { ok: false, reason: 'expired', label: found.label };
    return { ok: true, token: found };
  }
  async function lockTokenToDiscord(tok, discordId) {
    if (!/^\d{15,20}$/.test(discordId || '')) return { ok: false, reason: 'invalid_discord_id' };
    const tokens = _getTokens(), tokHash = await _hmac('access-token:' + String(tok || ''));
    const idx = tokens.findIndex(t => t.tokHash === tokHash);
    if (idx === -1) return { ok: false };
    if (!tokens[idx].lockedDiscord) {
      tokens[idx].lockedDiscord = discordId;
      _setTokens(tokens);
      return { ok: true, firstLock: true };
    }
    if (tokens[idx].lockedDiscord !== discordId) return { ok: false, reason: 'discord_mismatch' };
    return { ok: true };
  }
  async function revokeToken(tok) {
    const tokens = _getTokens(), tokHash = await _hmac('access-token:' + String(tok || ''));
    const idx = tokens.findIndex(t => t.tokHash === tokHash);
    if (idx !== -1) { tokens[idx].revoked = true; _setTokens(tokens); }
  }
  async function deleteToken(tok) {
    const tokHash = await _hmac('access-token:' + String(tok || ''));
    _setTokens(_getTokens().filter(t => t.tokHash !== tokHash));
  }

  // ── Announcement / Stock Update (now salted) ─────────────────────────────────
  function getAnnouncement()      { return localStorage.getItem(_S.ann()) || ''; }
  function setAnnouncement(text)  { if (text) localStorage.setItem(_S.ann(), String(text).slice(0, 500)); else localStorage.removeItem(_S.ann()); }
  function getStockUpdate()       { return localStorage.getItem(_S.su()) || ''; }
  function setStockUpdate(text)   { if (text) localStorage.setItem(_S.su(), String(text).slice(0, 500)); else localStorage.removeItem(_S.su()); }

  // ── Bug Reports ──────────────────────────────────────────────────────────────
  function getBugReports()    { try { return JSON.parse(localStorage.getItem(_S.bugs()) || '[]'); } catch { return []; } }
  function setBugReports(arr) { localStorage.setItem(_S.bugs(), JSON.stringify(arr)); }
  function addBugReport(report) {
    const reports = getBugReports();
    reports.unshift({
      id:        Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join(''),
      discordId: /^\d{15,20}$/.test(report.discordId || '') ? report.discordId : '',
      username:  (report.username  || '').slice(0, 64),
      category:  (report.category  || 'General').slice(0, 32),
      title:     (report.title     || '').slice(0, 128),
      body:      (report.body      || '').slice(0, 2000),
      ts:        Date.now(),
      status:    'open',
    });
    setBugReports(reports.slice(0, 500));
  }
  function updateBugStatus(id, status) {
    const reports = getBugReports();
    const idx     = reports.findIndex(r => r.id === id);
    if (idx !== -1) { reports[idx].status = status; setBugReports(reports); }
  }
  function clearBugReports() { setBugReports([]); }

  // ── Chat ─────────────────────────────────────────────────────────────────────
  function getChat() { try { return JSON.parse(localStorage.getItem(_S.chat()) || '[]'); } catch { return []; } }
  function setChat(arr) { localStorage.setItem(_S.chat(), JSON.stringify(arr.slice(-200))); }
  function addChatMessage(msg) {
    const chat = getChat();
    chat.push({
      id:        Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join(''),
      discordId: (msg.discordId || '').slice(0, 24),
      username:  (msg.username  || 'Anonymous').slice(0, 64),
      avatar:    (msg.avatar    || '').slice(0, 256),
      text:      (msg.text      || '').slice(0, 500),
      ts:        Date.now(),
    });
    setChat(chat);
  }

  // ── Admin-only: generate + add key, returns raw key once ────────────────────
  async function genAndAddKey(tier, pcId, discordId, rockstarCodeAccess) {
    const raw = _generateKey();
    const result = await addKey(raw, tier, pcId, discordId, rockstarCodeAccess);
    return result; // raw key string or null on duplicate (effectively impossible)
  }

  // Expose bootstrap only on the setup page and only before initialization.
  if (/(^|\/)setup\.html$/i.test(location.pathname) && !ownerReady) {
    window.MS_SETUP = Object.freeze({ bootstrap: _setOwnerSecret });
  }

  // ── Public frozen interface ───────────────────────────────────────────────────
  return Object.freeze({
    // Stock
    getStock, setStock, addStock, popStock, countStock,
    // Keys
    getKeys, addKey, updateKeyBinding, getKeyData, getKeyDataBySig, validateKey,
    markKeyUsed, deleteKey, genAndAddKey, revokeKey, resetKeyLock,
    lockKeyToDiscord, lockKeyToDiscordByKey, setRockstarCodeAccess,
    // Owner setup status; bootstrap is never exposed on the public MS object.
    ownerReady,
    // Session
    setSession, getSession, getSessionMeta, clearSession, isAdmin,
    // Token sessions
    setTokenSession, getTokenSession, clearTokenSession,
    // Access tokens
    addToken, getToken, validateToken, lockTokenToDiscord,
    revokeToken, deleteToken,
    // Announcement / Stock Update
    getAnnouncement, setAnnouncement,
    getStockUpdate, setStockUpdate,
    // Bug reports
    getBugReports, addBugReport, updateBugStatus, clearBugReports,
    // Chat
    getChat, addChatMessage,
    // Constants
    TIER_LIMITS, TIER_LABELS,
    TYPES: ['discord', 'steam', 'rockstar', 'rockstar_code'],
    dailyKey : d  => _S.daily(d),
    histKey  : ()  => _S.hist(),
    histDate : ()  => _S.hdate(),
  });
})();
