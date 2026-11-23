import app from './app.js';
import { pool } from './db.js';

const port = Number(process.env.PORT || 3000);
const server = app.listen(port, () => console.log(`MAX SHOP API listening on ${port}`));

async function shutdown(signal) {
  console.log(`${signal}: shutting down`);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
