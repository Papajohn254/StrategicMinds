#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const { Client } = require("pg");
const { initDb } = require("../db");

const sqlitePath = process.env.SQLITE_PATH || path.join(__dirname, "..", "data", "inventory.db");
const pgUrl = process.env.DATABASE_URL;

if(!pgUrl){
  console.error("DATABASE_URL is required.");
  process.exit(1);
}
if(!fs.existsSync(sqlitePath)){
  console.error(`SQLite file not found at ${sqlitePath}`);
  process.exit(1);
}

(async () => {
  initDb();

  const sqlite = new Database(sqlitePath, { readonly: true });
  const pg = new Client({ connectionString: pgUrl, ssl: { rejectUnauthorized: false } });
  await pg.connect();

  const tableOrder = [
    "branches",
    "suppliers",
    "warehouses",
    "users",
    "customers",
    "products",
    "product_prices",
    "sales",
    "sale_items",
    "returns",
    "return_items",
    "purchase_orders",
    "inventory_movements",
    "shopfront_orders",
    "attendance",
    "message_threads",
    "message_participants",
    "messages",
    "message_reads",
    "notifications",
    "activity_logs",
    "webauthn_credentials",
    "webauthn_challenges",
    "face_embeddings",
    "feedback",
    "referrals",
    "referral_invites",
    "settings"
  ];

  const tables = sqlite.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(r => r.name);
  const orderedTables = [...new Set([...tableOrder.filter(t => tables.includes(t)), ...tables.filter(t => !tableOrder.includes(t))])];

  for(const table of orderedTables){
    const columnsInfo = sqlite.prepare(`PRAGMA table_info(${table})`).all();
    const columns = columnsInfo.map(c => c.name);
    if(columns.length === 0) continue;

    const rows = sqlite.prepare(`SELECT * FROM ${table}`).all();
    if(rows.length === 0) continue;

    const colList = columns.map(c => `"${c}"`).join(",");
    const placeholders = columns.map((_, i) => `$${i + 1}`).join(",");
    const insertSql = `INSERT INTO "${table}" (${colList}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`;

    for(const row of rows){
      const values = columns.map(c => row[c]);
      await pg.query(insertSql, values);
    }

    const pk = columnsInfo.find(c => c.pk === 1);
    if(pk){
      try{
        await pg.query(
          `SELECT setval(pg_get_serial_sequence($1,$2), (SELECT COALESCE(MAX("${pk.name}"),0) FROM "${table}"))`,
          [table, pk.name]
        );
      }catch(err){
        // ignore sequence reset errors
      }
    }

    console.log(`Migrated ${table}: ${rows.length} rows`);
  }

  await pg.end();
  sqlite.close();
  console.log("Migration completed.");
  process.exit(0);
})().catch(err => {
  console.error("Migration failed:", err.message || err);
  process.exit(1);
});
