import {pool} from './db.js';
import {hashPassword} from './security.js';
const [email,password]=process.argv.slice(2);
if(!email||!/^\\S+@\\S+\\.\\S+$/.test(email)||!password||password.length<12){console.error('Usage: npm run bootstrap-admin -- owner@example.com "long-password-at-least-12-chars"');process.exit(2);}
const client=await pool.connect();
try{
 await client.query('BEGIN');
 await client.query('LOCK TABLE admins IN EXCLUSIVE MODE');
 const old=await client.query('SELECT 1 FROM admins LIMIT 1');
 if(old.rowCount)throw new Error('Admin already exists; refusing bootstrap.');
 const hash=await hashPassword(password);
 const r=await client.query('INSERT INTO admins(email,password_hash) VALUES($1,$2) RETURNING id,email',[email,hash]);
 await client.query('COMMIT');
 console.log('Created first admin:',r.rows[0].email);
}catch(e){await client.query('ROLLBACK').catch(()=>{});console.error(e.message);process.exitCode=1;}
finally{client.release();await pool.end();}
