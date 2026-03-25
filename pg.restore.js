#!/usr/bin/env node
const { Client } = require("pg");

function sanitizeDatabaseUrl(raw){
  if(!raw) return null;
  try{
    const parsed = new URL(String(raw).trim());
    if(!/^postgres(ql)?:$/.test(parsed.protocol)) return null;
    parsed.searchParams.delete("channel_binding");
    parsed.searchParams.delete("sslmode");
    return parsed.toString();
  }catch(err){
    return null;
  }
}

const url = sanitizeDatabaseUrl(process.env.DATABASE_URL);
if(!url){
  process.exit(0);
}

const client = new Client({ connectionString: url, ssl: { rejectUnauthorized: false } });

(async () => {
  await client.connect();
  await client.query(`CREATE TABLE IF NOT EXISTS sqlite_backups (
    id INTEGER PRIMARY KEY,
    data BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  const res = await client.query("SELECT data FROM sqlite_backups WHERE id = 1");
  if(res.rows && res.rows[0] && res.rows[0].data){
    const data = res.rows[0].data;
    process.stdout.write(Buffer.isBuffer(data) ? data : Buffer.from(data));
  }
  await client.end();
  process.exit(0);
})().catch(async (err) => {
  console.error(err.message || err);
  try{ await client.end(); }catch(e){}
  process.exit(1);
});
