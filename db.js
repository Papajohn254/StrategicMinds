const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const Database = require("better-sqlite3");

const dataDir = path.join(__dirname, "data");
const configuredPath = process.env.DB_PATH && process.env.DB_PATH.trim()
  ? process.env.DB_PATH.trim()
  : null;
const dbPath = configuredPath ? path.resolve(configuredPath) : path.join(dataDir, "inventory.db");
const dbDir = path.dirname(dbPath);
if(!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, {recursive:true});

function hasValidDatabaseUrl(raw){
  if(!raw) return false;
  try{
    const parsed = new URL(String(raw).trim());
    return /^postgres(ql)?:$/.test(parsed.protocol);
  }catch(err){
    return false;
  }
}

// Restore SQLite from Postgres backup if configured and local DB is missing/empty
if(hasValidDatabaseUrl(process.env.DATABASE_URL)){
  try{
    const shouldRestore = !fs.existsSync(dbPath) || fs.statSync(dbPath).size === 0;
    if(shouldRestore){
      const scriptPath = path.join(__dirname, "scripts", "pg-restore.js");
      if(fs.existsSync(scriptPath)){
        const buf = execFileSync(process.execPath, [scriptPath], { env: process.env });
        if(buf && buf.length > 0){
          fs.writeFileSync(dbPath, buf);
          console.log("SQLite restored from Postgres backup.");
        }
      }
    }
  }catch(err){
    console.warn("Postgres restore skipped:", err.message || err);
  }
}

const db = new Database(dbPath);
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");

function initDb(){
  const now = () => new Date().toISOString();
  db.exec(`
  CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    location TEXT,
    manager_name TEXT,
    phone TEXT,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    last_login TEXT,
    branch_id INTEGER,
    username TEXT,
    staff_id TEXT,
    supplier_id INTEGER,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TEXT,
    password_changed_at TEXT,
    admin_locked INTEGER DEFAULT 0,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL,
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    challenge TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS message_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    type TEXT NOT NULL,
    created_by INTEGER,
    branch_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS message_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE(thread_id, user_id),
    FOREIGN KEY (thread_id) REFERENCES message_threads(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    sender_id INTEGER,
    sender_name TEXT,
    content TEXT NOT NULL,
    attachments TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (thread_id) REFERENCES message_threads(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS message_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    read_at TEXT NOT NULL,
    UNIQUE(message_id, user_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    title TEXT,
    message TEXT NOT NULL,
    link TEXT,
    status TEXT NOT NULL DEFAULT 'unread',
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    contact TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    lead_time INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS warehouses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    location TEXT,
    capacity INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    branch_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT,
    price REAL NOT NULL,
    cost_price REAL NOT NULL DEFAULT 0,
    quantity INTEGER NOT NULL DEFAULT 0,
    is_published INTEGER NOT NULL DEFAULT 1,
    owner_user_id INTEGER,
    supplier_id INTEGER,
    branch_id INTEGER,
    warehouse_id INTEGER,
    reorder_level INTEGER,
    min_stock INTEGER,
    max_stock INTEGER,
    safety_stock INTEGER,
    lead_time INTEGER,
    barcode TEXT UNIQUE,
    batch_no TEXT,
    expiry_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id) ON DELETE SET NULL,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL,
    FOREIGN KEY (warehouse_id) REFERENCES warehouses(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT,
    address TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE,
    customer_id INTEGER,
    customer_name TEXT,
    cashier_id INTEGER,
    cashier_name TEXT,
    branch_id INTEGER,
    payment_mode TEXT,
    subtotal REAL NOT NULL,
    discount REAL NOT NULL DEFAULT 0,
    tax REAL NOT NULL DEFAULT 0,
    fees_total REAL NOT NULL DEFAULT 0,
    fees_breakdown TEXT,
    table_name TEXT,
    total REAL NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
    FOREIGN KEY (cashier_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS sale_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL,
    product_id INTEGER,
    product_name TEXT NOT NULL,
    qty INTEGER NOT NULL,
    price REAL NOT NULL,
    cost_price REAL NOT NULL DEFAULT 0,
    subtotal REAL NOT NULL,
    FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS product_prices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    branch_id INTEGER NOT NULL,
    price REAL NOT NULL,
    cost_price REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(product_id, branch_id),
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    branch_id INTEGER,
    date TEXT NOT NULL,
    clock_in TEXT NOT NULL,
    clock_out TEXT,
    total_hours REAL,
    status TEXT,
    device TEXT,
    location TEXT,
    method TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS face_embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    descriptor TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS returns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER,
    receipt_id TEXT,
    branch_id INTEGER,
    customer_name TEXT,
    cashier_name TEXT,
    reason TEXT,
    total_refund REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_name TEXT,
    role TEXT,
    message TEXT NOT NULL,
    response TEXT NOT NULL,
    context_page TEXT,
    branch_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS return_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    return_id INTEGER NOT NULL,
    product_id INTEGER,
    product_name TEXT NOT NULL,
    qty INTEGER NOT NULL,
    price REAL NOT NULL,
    cost_price REAL NOT NULL DEFAULT 0,
    subtotal REAL NOT NULL,
    FOREIGN KEY (return_id) REFERENCES returns(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_name TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT,
    branch_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT,
    branch_id INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(key, branch_id),
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS mpesa_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    branch_id INTEGER,
    account_name TEXT NOT NULL,
    business_type TEXT NOT NULL DEFAULT 'paybill',
    shortcode TEXT NOT NULL,
    consumer_key TEXT,
    consumer_secret TEXT,
    passkey TEXT,
    environment TEXT NOT NULL DEFAULT 'sandbox',
    phone_number TEXT,
    account_reference TEXT,
    transaction_description TEXT,
    callback_url TEXT,
    validation_url TEXT,
    confirmation_url TEXT,
    enable_stk_push INTEGER NOT NULL DEFAULT 1,
    enable_c2b INTEGER NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'KES',
    auto_confirm_payments INTEGER NOT NULL DEFAULT 0,
    is_default INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS mpesa_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    account_id INTEGER,
    branch_id INTEGER,
    order_id INTEGER,
    sale_id INTEGER,
    phone_number TEXT,
    amount REAL,
    reference TEXT,
    mpesa_receipt TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    result_code TEXT,
    result_desc TEXT,
    request_payload TEXT,
    response_payload TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (account_id) REFERENCES mpesa_accounts(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL,
    FOREIGN KEY (order_id) REFERENCES shopfront_orders(id) ON DELETE SET NULL,
    FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_name TEXT,
    branch_id INTEGER,
    rating INTEGER,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS referral_invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referral_id INTEGER NOT NULL,
    name TEXT,
    contact TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (referral_id) REFERENCES referrals(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    requester_name TEXT,
    contact TEXT,
    branch_id INTEGER,
    details TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS shopfront_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_name TEXT,
    contact TEXT,
    items_json TEXT NOT NULL,
    subtotal REAL NOT NULL,
    total REAL NOT NULL,
    branch_id INTEGER,
    status TEXT NOT NULL DEFAULT 'Order Placed',
    payment_method TEXT,
    payment_status TEXT,
    payment_reference TEXT,
    paid_amount REAL,
    paid_at TEXT,
    delivery_type TEXT,
    delivery_address TEXT,
    delivery_phone TEXT,
    delivery_fee REAL DEFAULT 0,
    tracking_timeline TEXT,
    assigned_rider_id INTEGER,
    assigned_rider_name TEXT,
    otp_code TEXT,
    stock_committed INTEGER,
    cancelled_at TEXT,
    delivered_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS purchase_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_number TEXT NOT NULL UNIQUE,
    supplier_id INTEGER NOT NULL,
    supplier_name TEXT,
    product_id INTEGER NOT NULL,
    product_name TEXT,
    branch_id INTEGER,
    qty INTEGER NOT NULL,
    eta_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    requested_by INTEGER,
    requested_by_name TEXT,
    created_at TEXT NOT NULL,
    received_at TEXT,
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS inventory_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    product_name TEXT NOT NULL,
    type TEXT NOT NULL,
    qty INTEGER NOT NULL,
    reference TEXT,
    note TEXT,
    user_id INTEGER,
    user_name TEXT,
    branch_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
  );
  `);

  function columnExists(table, column){
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    return cols.some(c => c.name === column);
  }

  function ensureColumn(table, column, type){
    if(!columnExists(table, column)){
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
    }
  }

  // Backward-compatible migrations
  ensureColumn("users", "branch_id", "INTEGER");
  ensureColumn("users", "phone", "TEXT");
  ensureColumn("users", "username", "TEXT");
  ensureColumn("users", "staff_id", "TEXT");
  ensureColumn("users", "failed_login_attempts", "INTEGER");
  ensureColumn("users", "locked_until", "TEXT");
  ensureColumn("users", "password_changed_at", "TEXT");
  ensureColumn("users", "admin_locked", "INTEGER DEFAULT 0");
  ensureColumn("products", "branch_id", "INTEGER");
  ensureColumn("products", "cost_price", "REAL");
  ensureColumn("products", "is_published", "INTEGER");
  ensureColumn("products", "owner_user_id", "INTEGER");
  ensureColumn("users", "supplier_id", "INTEGER");
  ensureColumn("products", "batch_no", "TEXT");
  ensureColumn("products", "expiry_date", "TEXT");
  ensureColumn("products", "warehouse_id", "INTEGER");
  ensureColumn("products", "min_stock", "INTEGER");
  ensureColumn("products", "max_stock", "INTEGER");
  ensureColumn("products", "safety_stock", "INTEGER");
  ensureColumn("sales", "branch_id", "INTEGER");
  ensureColumn("sales", "payment_mode", "TEXT");
  ensureColumn("sales", "fees_total", "REAL");
  ensureColumn("sales", "fees_breakdown", "TEXT");
  ensureColumn("sales", "table_name", "TEXT");
  ensureColumn("purchase_orders", "branch_id", "INTEGER");
  ensureColumn("inventory_movements", "branch_id", "INTEGER");
  ensureColumn("sale_items", "cost_price", "REAL");
  ensureColumn("shopfront_orders", "delivery_type", "TEXT");
  ensureColumn("shopfront_orders", "delivery_address", "TEXT");
  ensureColumn("shopfront_orders", "delivery_phone", "TEXT");
  ensureColumn("shopfront_orders", "delivery_fee", "REAL");
  ensureColumn("shopfront_orders", "tracking_timeline", "TEXT");
  ensureColumn("shopfront_orders", "assigned_rider_id", "INTEGER");
  ensureColumn("shopfront_orders", "assigned_rider_name", "TEXT");
  ensureColumn("shopfront_orders", "otp_code", "TEXT");
  ensureColumn("shopfront_orders", "payment_method", "TEXT");
  ensureColumn("shopfront_orders", "payment_status", "TEXT");
  ensureColumn("shopfront_orders", "payment_reference", "TEXT");
  ensureColumn("shopfront_orders", "paid_amount", "REAL");
  ensureColumn("shopfront_orders", "paid_at", "TEXT");
  ensureColumn("shopfront_orders", "stock_committed", "INTEGER");
  ensureColumn("shopfront_orders", "cancelled_at", "TEXT");
  ensureColumn("shopfront_orders", "delivered_at", "TEXT");
  ensureColumn("shopfront_orders", "updated_at", "TEXT");
  ensureColumn("shopfront_orders", "mpesa_account_id", "INTEGER");
  ensureColumn("feedback", "status", "TEXT DEFAULT 'pending'");
  ensureColumn("users", "admin_locked", "INTEGER DEFAULT 0");

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_products_branch ON products(branch_id);
    CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode);
    CREATE INDEX IF NOT EXISTS idx_products_published ON products(is_published);
    CREATE INDEX IF NOT EXISTS idx_sales_branch_created ON sales(branch_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_movements_branch_created ON inventory_movements(branch_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items(sale_id);
    CREATE INDEX IF NOT EXISTS idx_purchase_orders_branch_created ON purchase_orders(branch_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_customers_created ON customers(created_at);
    CREATE INDEX IF NOT EXISTS idx_shopfront_orders_branch_created ON shopfront_orders(branch_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
    CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);
    CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_type ON webauthn_challenges(user_id, type);
    CREATE INDEX IF NOT EXISTS idx_face_embeddings_user ON face_embeddings(user_id);
    CREATE INDEX IF NOT EXISTS idx_mpesa_accounts_user_branch ON mpesa_accounts(user_id, branch_id);
    CREATE INDEX IF NOT EXISTS idx_mpesa_accounts_status ON mpesa_accounts(status, is_default);
    CREATE INDEX IF NOT EXISTS idx_mpesa_transactions_account_created ON mpesa_transactions(account_id, created_at);
  `);

  // Ensure at least one branch exists
  const branchCount = db.prepare("SELECT COUNT(*) as count FROM branches").get();
  if(branchCount.count === 0){
    db.prepare(`INSERT INTO branches (name,location,manager_name,phone,email,status,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run("Main Branch", "Head Office", "Admin", "-", "-", "active", now(), now());
  }

  const defaultBranch = db.prepare("SELECT id FROM branches ORDER BY id ASC LIMIT 1").get();
  if(defaultBranch && defaultBranch.id){
    const bid = defaultBranch.id;
    db.prepare("UPDATE users SET branch_id = ? WHERE branch_id IS NULL").run(bid);
    db.prepare("UPDATE products SET branch_id = ? WHERE branch_id IS NULL").run(bid);
    db.prepare("UPDATE sales SET branch_id = ? WHERE branch_id IS NULL").run(bid);
    db.prepare("UPDATE purchase_orders SET branch_id = ? WHERE branch_id IS NULL").run(bid);
    db.prepare("UPDATE inventory_movements SET branch_id = ? WHERE branch_id IS NULL").run(bid);
  }

  db.prepare("UPDATE products SET cost_price = 0 WHERE cost_price IS NULL").run();
  db.prepare("UPDATE sale_items SET cost_price = 0 WHERE cost_price IS NULL").run();
  db.prepare("UPDATE users SET failed_login_attempts = 0 WHERE failed_login_attempts IS NULL").run();
}

module.exports = { db, initDb };
