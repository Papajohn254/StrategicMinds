#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
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
const dbPath = process.env.DB_PATH && process.env.DB_PATH.trim()
  ? process.env.DB_PATH.trim()
  : path.join(__dirname, "..", "data", "inventory.db");

if(!url){
  process.exit(0);
}
if(!fs.existsSync(dbPath)){
  process.exit(0);
}

const client = new Client({ connectionString: url, ssl: { rejectUnauthorized: false } });

(async () => {
  const data = fs.readFileSync(dbPath);
  await client.connect();
  await client.query(`CREATE TABLE IF NOT EXISTS sqlite_backups (
    id INTEGER PRIMARY KEY,
    data BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await client.query(
    "INSERT INTO sqlite_backups (id,data,updated_at) VALUES (1,$1,NOW()) ON CONFLICT (id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
    [data]
  );
  await client.end();
  process.exit(0);
})().catch(async (err) => {
  console.error(err.message || err);
  try{ await client.end(); }catch(e){}
  process.exit(1);
});
