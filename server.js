const express = require("express");
require("dotenv").config();
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");
const compression = require("compression");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { spawn } = require("child_process");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require("@simplewebauthn/server");
const { isoBase64URL } = require("@simplewebauthn/server/helpers");
const { db, initDb } = require("./db");

console.log("Server starting...");

const app = express();
const PORT = process.env.PORT || 8010;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const MPESA_ENCRYPTION_SECRET = process.env.MPESA_ENCRYPTION_SECRET || JWT_SECRET;
const WEB_AUTHN_ORIGIN = process.env.WEB_AUTHN_ORIGIN || "";
const WEB_AUTHN_RPID = process.env.WEB_AUTHN_RPID || "";
const FACE_MATCH_THRESHOLD = Number(process.env.FACE_MATCH_THRESHOLD || 0.55);
const VENDOR_ROLES = ["supplier","seller","retailer","wholesaler"];
const ADMIN_BOOTSTRAP_USERNAME = process.env.ADMIN_BOOTSTRAP_USERNAME || "admin@site";
const ADMIN_BOOTSTRAP_EMAIL = process.env.ADMIN_BOOTSTRAP_EMAIL || "admin@site";
const ADMIN_BOOTSTRAP_PASSWORD = process.env.ADMIN_BOOTSTRAP_PASSWORD || "2006@shawn_M";
const ADMIN_BOOTSTRAP_FORCE = String(process.env.ADMIN_BOOTSTRAP_FORCE || "false") === "true";

initDb();

app.use(cors());
app.use(compression());
app.use(express.json({ limit: "10mb" }));

// Test route
app.get("/api/test", (req, res) => {
  res.json({ message: "API is working" });
});

const now = () => new Date().toISOString();
const today = () => new Date().toISOString().slice(0,10);

const DEFAULT_SETTINGS = {
  receipt_prefix: "RCPT",
  receipt_footer: "Thank you for shopping!",
  site_footer_text: "Copyright © 2026 SmartInventory Pro. All rights reserved.",
  announcement_text: "Welcome to SmartInventory Pro - Modern POS & Inventory for every branch.",
  announcement_enabled: true,
  announcement_speed: 22,
  tax_rate_default: 0,
  discount_default: 0,
  round_off_enabled: false,
  table_management_enabled: false,
  inventory_health_enabled: true,
  payment_modes: ["Cash", "M-PESA", "Debit Card", "Credit Card"],
  delivery_fee: 0,
  packing_fee: 0,
  service_fee: 0,
  other_fee: 0,
  language: "English",
  weighing_machine_enabled: false,
  printer_enabled: false,
  printer_name: "",
  shopfront_enabled: true,
  kitchen_display_enabled: false,
  privacy_policy: `<h2>Privacy Policy</h2>
<p><strong>Effective Date:</strong> January 1, 2024</p>

<h3>1. Information We Collect</h3>
<p>We collect information you provide directly to us, such as when you create an account, make a purchase, or contact us for support. This may include your name, email address, phone number, and payment information.</p>

<h3>2. How We Use Your Information</h3>
<p>We use the information we collect to:</p>
<ul>
<li>Provide, maintain, and improve our services</li>
<li>Process transactions and send related information</li>
<li>Send you technical notices and support messages</li>
<li>Communicate with you about products, services, and promotions</li>
</ul>

<h3>3. Information Sharing</h3>
<p>We do not sell, trade, or otherwise transfer your personal information to third parties without your consent, except as described in this policy.</p>

<h3>4. Data Security</h3>
<p>We implement appropriate security measures to protect your personal information against unauthorized access, alteration, disclosure, or destruction.</p>

<h3>5. Contact Us</h3>
<p>If you have any questions about this Privacy Policy, please contact us at privacy@smartinventory.com.</p>`,
  terms_conditions: `<h2>Terms & Conditions</h2>
<p><strong>Effective Date:</strong> January 1, 2024</p>

<h3>1. Acceptance of Terms</h3>
<p>By accessing and using SmartInventory Pro, you accept and agree to be bound by the terms and provision of this agreement.</p>

<h3>2. Use License</h3>
<p>Permission is granted to temporarily use SmartInventory Pro for personal and business use. This license shall automatically terminate if you violate any of these restrictions.</p>

<h3>3. User Responsibilities</h3>
<p>You are responsible for:</p>
<ul>
<li>Maintaining the confidentiality of your account credentials</li>
<li>All activities that occur under your account</li>
<li>Ensuring the accuracy of data entered into the system</li>
<li>Complying with all applicable laws and regulations</li>
</ul>

<h3>4. Service Availability</h3>
<p>While we strive to provide continuous service, we do not guarantee that the service will be uninterrupted or error-free. We reserve the right to modify or discontinue the service with notice.</p>

<h3>5. Limitation of Liability</h3>
<p>In no event shall SmartInventory Pro be liable for any indirect, incidental, special, or consequential damages arising out of or in connection with your use of the service.</p>

<h3>6. Contact Information</h3>
<p>For questions about these Terms & Conditions, please contact us at legal@smartinventory.com.</p>`
};

function parseSettingValue(raw){
  if(raw === null || raw === undefined) return null;
  try{
    return JSON.parse(raw);
  }catch(err){
    return raw;
  }
}

function getSettingsForBranch(branchId){
  const id = Number(branchId) || 0;
  const rows = id
    ? db.prepare("SELECT key,value,branch_id FROM settings WHERE branch_id IN (0, ?)").all(id)
    : db.prepare("SELECT key,value,branch_id FROM settings WHERE branch_id = 0").all();
  const settings = { ...DEFAULT_SETTINGS };
  rows.filter(r => Number(r.branch_id) === 0).forEach(r => {
    settings[r.key] = parseSettingValue(r.value);
  });
  if(id){
    rows.filter(r => Number(r.branch_id) === id).forEach(r => {
      settings[r.key] = parseSettingValue(r.value);
    });
  }
  return settings;
}

function saveSettings(settings, branchId){
  const id = Number(branchId) || 0;
  const keys = Object.keys(settings || {});
  const stmt = db.prepare(`INSERT INTO settings (key,value,branch_id,updated_at)
    VALUES (?,?,?,?)
    ON CONFLICT(key, branch_id) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`);
  keys.forEach(key => {
    const value = JSON.stringify(settings[key]);
    stmt.run(key, value, id, now());
  });
}

function sendError(res, code, message){
  return res.status(code).json({ error: message });
}

function resolveLegalBranchId(req){
  const raw = req.query && req.query.branch_id;
  if(raw === undefined || raw === null || raw === "" || raw === "all") return 0;
  const id = Number(raw);
  return Number.isFinite(id) && id > 0 ? id : 0;
}

function hasValidDatabaseUrl(raw){
  if(!raw) return false;
  try{
    const parsed = new URL(String(raw).trim());
    return /^postgres(ql)?:$/.test(parsed.protocol);
  }catch(err){
    return false;
  }
}

function parsePagination(req, maxLimit = 1000){
  const limitRaw = req.query.limit;
  const offsetRaw = req.query.offset;
  const limit = Number(limitRaw);
  const offset = Number(offsetRaw);
  if(Number.isFinite(limit) && limit > 0){
    return {
      limit: Math.min(limit, maxLimit),
      offset: Number.isFinite(offset) && offset > 0 ? Math.floor(offset) : 0
    };
  }
  return { limit: null, offset: 0 };
}

function getExpectedOrigin(req){
  if(WEB_AUTHN_ORIGIN) return WEB_AUTHN_ORIGIN;
  if(req.headers.origin) return req.headers.origin;
  if(APP_BASE_URL) return APP_BASE_URL;
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "http";
  return `${proto}://${req.headers.host}`;
}

function getExpectedRpId(req){
  if(WEB_AUTHN_RPID) return WEB_AUTHN_RPID;
  try{
    return new URL(getExpectedOrigin(req)).hostname;
  }catch(err){
    return req.hostname || "localhost";
  }
}

function getAppBaseUrl(){
  return String(APP_BASE_URL || "").replace(/\/+$/, "");
}

function getMpesaKey(){
  return crypto.createHash("sha256").update(String(MPESA_ENCRYPTION_SECRET || JWT_SECRET)).digest();
}

function encryptSecret(value){
  const plain = String(value || "").trim();
  if(!plain) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getMpesaKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
}

function decryptSecret(value){
  if(!value) return "";
  const raw = String(value);
  if(!raw.startsWith("v1:")) return raw;
  const parts = raw.split(":");
  if(parts.length !== 4) return "";
  try{
    const [, ivRaw, tagRaw, dataRaw] = parts;
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      getMpesaKey(),
      Buffer.from(ivRaw, "base64")
    );
    decipher.setAuthTag(Buffer.from(tagRaw, "base64"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(dataRaw, "base64")),
      decipher.final()
    ]);
    return decrypted.toString("utf8");
  }catch(err){
    return "";
  }
}

function maskSecret(value){
  const raw = String(value || "");
  if(!raw) return "";
  if(raw.length <= 4) return "****";
  return `${raw.slice(0, 2)}${"*".repeat(Math.max(4, raw.length - 4))}${raw.slice(-2)}`;
}

function normalizeMpesaBusinessType(value){
  return String(value || "").toLowerCase() === "till" ? "till" : "paybill";
}

function normalizeMpesaEnvironment(value){
  return String(value || "").toLowerCase() === "live" ? "live" : "sandbox";
}

function isMpesaMethod(value){
  const method = String(value || "").toLowerCase();
  return method.includes("mpesa") || method.includes("m-pesa");
}

function buildMpesaUrls(accountId){
  const base = getAppBaseUrl();
  return {
    callback_url: `${base}/api/mpesa/accounts/${accountId}/callback`,
    validation_url: `${base}/api/mpesa/accounts/${accountId}/validation`,
    confirmation_url: `${base}/api/mpesa/accounts/${accountId}/confirmation`
  };
}

function sanitizeMpesaAccount(row){
  if(!row) return null;
  return {
    id: row.id,
    user_id: row.user_id,
    user_name: row.user_name,
    branch_id: row.branch_id,
    branch_name: row.branch_name,
    account_name: row.account_name,
    business_type: row.business_type,
    shortcode: row.shortcode,
    environment: row.environment,
    phone_number: row.phone_number || "",
    account_reference: row.account_reference || "",
    transaction_description: row.transaction_description || "",
    callback_url: row.callback_url || "",
    validation_url: row.validation_url || "",
    confirmation_url: row.confirmation_url || "",
    enable_stk_push: !!row.enable_stk_push,
    enable_c2b: !!row.enable_c2b,
    currency: row.currency || "KES",
    auto_confirm_payments: !!row.auto_confirm_payments,
    is_default: !!row.is_default,
    status: row.status || "active",
    has_consumer_key: !!decryptSecret(row.consumer_key || ""),
    has_consumer_secret: !!decryptSecret(row.consumer_secret || ""),
    has_passkey: !!decryptSecret(row.passkey || ""),
    consumer_key_masked: maskSecret(decryptSecret(row.consumer_key || "")),
    consumer_secret_masked: maskSecret(decryptSecret(row.consumer_secret || "")),
    passkey_masked: maskSecret(decryptSecret(row.passkey || "")),
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function canManageMpesaAccount(user, account){
  if(!user || !account) return false;
  if(user.role === "admin") return true;
  return Number(account.user_id) === Number(user.id);
}

function setMpesaDefaultAccount(userId, branchId, accountId){
  const branchValue = Number(branchId) || 0;
  if(branchValue){
    db.prepare("UPDATE mpesa_accounts SET is_default = 0 WHERE user_id = ? AND COALESCE(branch_id, 0) = ?")
      .run(userId, branchValue);
  }else{
    db.prepare("UPDATE mpesa_accounts SET is_default = 0 WHERE user_id = ? AND (branch_id IS NULL OR branch_id = 0)")
      .run(userId);
  }
  db.prepare("UPDATE mpesa_accounts SET is_default = 1, updated_at = ? WHERE id = ?").run(now(), accountId);
}

function getMpesaAccountById(accountId){
  return db.prepare(`
    SELECT a.*, u.name as user_name, b.name as branch_name
    FROM mpesa_accounts a
    LEFT JOIN users u ON u.id = a.user_id
    LEFT JOIN branches b ON b.id = a.branch_id
    WHERE a.id = ?
  `).get(accountId);
}

function getDefaultMpesaAccountForBranch(branchId){
  const branchValue = Number(branchId) || 0;
  if(branchValue){
    const branchDefault = db.prepare(`
      SELECT a.*, u.name as user_name, b.name as branch_name
      FROM mpesa_accounts a
      LEFT JOIN users u ON u.id = a.user_id
      LEFT JOIN branches b ON b.id = a.branch_id
      WHERE a.status = 'active' AND a.branch_id = ? AND a.is_default = 1
      ORDER BY a.updated_at DESC, a.id DESC
      LIMIT 1
    `).get(branchValue);
    if(branchDefault) return branchDefault;

    const branchAny = db.prepare(`
      SELECT a.*, u.name as user_name, b.name as branch_name
      FROM mpesa_accounts a
      LEFT JOIN users u ON u.id = a.user_id
      LEFT JOIN branches b ON b.id = a.branch_id
      WHERE a.status = 'active' AND a.branch_id = ?
      ORDER BY a.is_default DESC, a.updated_at DESC, a.id DESC
      LIMIT 1
    `).get(branchValue);
    if(branchAny) return branchAny;
  }

  return db.prepare(`
    SELECT a.*, u.name as user_name, b.name as branch_name
    FROM mpesa_accounts a
    LEFT JOIN users u ON u.id = a.user_id
    LEFT JOIN branches b ON b.id = a.branch_id
    WHERE a.status = 'active' AND (a.branch_id IS NULL OR a.branch_id = 0)
    ORDER BY a.is_default DESC, a.updated_at DESC, a.id DESC
    LIMIT 1
  `).get();
}

function recordMpesaTransaction({
  user_id,
  account_id,
  branch_id,
  order_id,
  sale_id,
  phone_number,
  amount,
  reference,
  mpesa_receipt,
  status,
  result_code,
  result_desc,
  request_payload,
  response_payload
}){
  return db.prepare(`
    INSERT INTO mpesa_transactions (
      user_id, account_id, branch_id, order_id, sale_id, phone_number, amount, reference,
      mpesa_receipt, status, result_code, result_desc, request_payload, response_payload,
      created_at, updated_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    user_id || null,
    account_id || null,
    branch_id || null,
    order_id || null,
    sale_id || null,
    phone_number || "",
    Number.isFinite(Number(amount)) ? Number(amount) : null,
    reference || "",
    mpesa_receipt || "",
    status || "pending",
    result_code || null,
    result_desc || null,
    request_payload ? JSON.stringify(request_payload) : null,
    response_payload ? JSON.stringify(response_payload) : null,
    now(),
    now()
  );
}

function parseFaceDescriptor(input){
  if(!Array.isArray(input)) return null;
  if(input.length < 64) return null;
  const vector = input.map(v => Number(v));
  if(vector.some(v => !Number.isFinite(v))) return null;
  return vector;
}

function euclideanDistance(a, b){
  const len = Math.min(a.length, b.length);
  let sum = 0;
  for(let i = 0; i < len; i++){
    const diff = a[i] - b[i];
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

function authMiddleware(req, res, next){
  const authHeader = req.headers.authorization || "";
  const token = authHeader.split(" ")[1];
  if(!token) return sendError(res, 401, "Unauthorized");
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  }catch(err){
    return sendError(res, 401, "Invalid token");
  }
}

function requireRole(roles){
  return (req, res, next) => {
    if(!req.user || !roles.includes(req.user.role)){
      return sendError(res, 403, "Forbidden");
    }
    next();
  };
}

function resolveBranchId(req){
  const q = req.query.branch_id;
  if(q !== undefined && q !== null && q !== ""){
    if(q === "all" || q === "0") return null;
    const id = Number(q);
    return Number.isFinite(id) ? id : null;
  }
  if(req.user && Number.isFinite(Number(req.user.branch_id))){
    return Number(req.user.branch_id);
  }
  return null;
}

function resolveBranchIdFromBody(req){
  const bodyId = req.body && req.body.branch_id;
  if(bodyId !== undefined && bodyId !== null && bodyId !== ""){
    if(bodyId === "all" || bodyId === "0") return null;
    const id = Number(bodyId);
    return Number.isFinite(id) ? id : null;
  }
  if(req.user && Number.isFinite(Number(req.user.branch_id))){
    return Number(req.user.branch_id);
  }
  return null;
}

function getBranchById(id){
  if(!id) return null;
  return db.prepare("SELECT * FROM branches WHERE id = ?").get(id);
}

function getWarehouseById(id){
  if(!id) return null;
  return db.prepare("SELECT * FROM warehouses WHERE id = ?").get(id);
}

function normalizeDateStart(value){
  if(!value) return null;
  return value.length <= 10 ? `${value}T00:00:00.000Z` : value;
}

function normalizeDateEnd(value){
  if(!value) return null;
  return value.length <= 10 ? `${value}T23:59:59.999Z` : value;
}

function buildDateWhere(column, from, to){
  const clauses = [];
  const params = [];
  const start = normalizeDateStart(from);
  const end = normalizeDateEnd(to);
  if(start){
    clauses.push(`${column} >= ?`);
    params.push(start);
  }
  if(end){
    clauses.push(`${column} <= ?`);
    params.push(end);
  }
  return { clauses, params };
}

function csvEscape(value){
  if(value === null || value === undefined) return "";
  const str = String(value);
  if(str.includes("\"") || str.includes(",") || str.includes("\n")){
    return `"${str.replace(/\"/g, "\"\"")}"`;
  }
  return str;
}

function sendCsv(res, filename, rows, columns){
  const header = columns.map(c => c.label).join(",");
  const lines = rows.map(row => columns.map(c => csvEscape(row[c.key])).join(","));
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename=\"${filename}\"`);
  res.send([header, ...lines].join("\n"));
}

function parseCsv(text){
  const rows = [];
  let row = [];
  let cur = "";
  let inQuotes = false;
  for(let i=0;i<text.length;i++){
    const ch = text[i];
    const next = text[i+1];
    if(ch === '"' && inQuotes && next === '"'){
      cur += '"';
      i++;
      continue;
    }
    if(ch === '"'){
      inQuotes = !inQuotes;
      continue;
    }
    if(ch === ',' && !inQuotes){
      row.push(cur);
      cur = "";
      continue;
    }
    if((ch === '\n' || ch === '\r') && !inQuotes){
      if(ch === '\r' && next === '\n'){ i++; }
      row.push(cur);
      if(row.some(v => v.trim() !== "")) rows.push(row);
      row = [];
      cur = "";
      continue;
    }
    cur += ch;
  }
  if(cur.length || row.length){
    row.push(cur);
    if(row.some(v => v.trim() !== "")) rows.push(row);
  }
  return rows;
}

function logActivity(user, action, entityType, entityId, details, branchId){
  try{
    db.prepare(`INSERT INTO activity_logs (user_id,user_name,action,entity_type,entity_id,details,branch_id,created_at)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(
        user ? user.id : null,
        user ? user.name : null,
        action,
        entityType || null,
        entityId || null,
        details || null,
        branchId || (user ? user.branch_id : null),
        now()
      );
  }catch(err){
    // avoid breaking primary flow if logging fails
  }
}

function generateBarcode(){
  return "BC" + Math.floor(100000 + Math.random() * 900000);
}

function generateUniqueBarcode(){
  let code = generateBarcode();
  let tries = 0;
  while(db.prepare("SELECT id FROM products WHERE barcode = ?").get(code) && tries < 10){
    code = generateBarcode();
    tries++;
  }
  return code;
}

function isStrongPassword(password){
  if(!password || password.length < 8) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  return hasUpper && hasLower && hasNumber;
}

function bootstrapAdmin(){
  const email = String(ADMIN_BOOTSTRAP_EMAIL || "").trim().toLowerCase();
  const password = String(ADMIN_BOOTSTRAP_PASSWORD || "");
  if(!email || !password) return;

  // Always create/update the permanent admin regardless of password strength for deployment
  const branch = db.prepare("SELECT id FROM branches ORDER BY id ASC LIMIT 1").get();
  if(!branch) return;

  const username = String(ADMIN_BOOTSTRAP_USERNAME || email).trim();
  const existing = db.prepare("SELECT * FROM users WHERE LOWER(email) = ?").get(email);
  const hash = bcrypt.hashSync(password, 10);

  if(!existing){
    // Create permanent admin account
    db.prepare(`INSERT INTO users (name,email,password_hash,role,status,created_at,last_login,branch_id,username,password_changed_at,admin_locked)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run("System Administrator", email, hash, "admin", "active", now(), "-", branch.id, username || null, now(), 1);
    console.log(`✓ PERMANENT ADMIN CREATED: ${email} - This account is now LOCKED and cannot be modified or deleted`);
    return;
  }

  // PROTECTION: Never modify locked admin accounts after deployment
  if(existing.admin_locked){
    console.log(`✓ Admin ${email} is PERMANENTLY LOCKED - No changes applied. This account cannot be modified.`);
    return;
  }

  // Only allow initial setup on existing admin - never change after deployment
  const updates = [];
  const params = [];

  // Force permanent lock on admin account
  updates.push("admin_locked = ?");
  params.push(1);

  // Update other fields only if not already set
  if(existing.role !== "admin"){ updates.push("role = ?"); params.push("admin"); }
  if(existing.status !== "active"){ updates.push("status = ?"); params.push("active"); }
  if(username && existing.username !== username){ updates.push("username = ?"); params.push(username); }

  // Only update password if FORCE flag is set (for initial deployment only)
  if(ADMIN_BOOTSTRAP_FORCE){
    updates.push("password_hash = ?");
    updates.push("password_changed_at = ?");
    params.push(hash, now());
  }

  if(updates.length > 1){ // More than just the lock update
    params.push(existing.id);
    db.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).run(...params);
    console.log(`✓ Admin ${email} updated and PERMANENTLY LOCKED - No further changes allowed`);
  } else {
    // Just ensure it's locked
    db.prepare("UPDATE users SET admin_locked = 1 WHERE id = ?").run(existing.id);
    console.log(`✓ Admin ${email} is now PERMANENTLY LOCKED`);
  }
}

function generateResetCode(){
  return String(Math.floor(100000 + Math.random() * 900000));
}

function isVendorRole(role){
  return VENDOR_ROLES.includes(String(role || "").toLowerCase());
}

function generateUniqueUsername(base){
  const clean = String(base || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
  let username = clean || `user${Math.floor(Math.random() * 10000)}`;
  let tries = 0;
  while(tries < 5){
    const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
    if(!exists) return username;
    username = `${clean || "user"}${Math.floor(100 + Math.random()*900)}`;
    tries++;
  }
  return `${clean || "user"}${Date.now().toString().slice(-4)}`;
}

function createNotification({ user_id, type, title, message, link }){
  if(!user_id || !type || !message) return;
  db.prepare(`INSERT INTO notifications (user_id,type,title,message,link,status,created_at)
    VALUES (?,?,?,?,?,'unread',?)`)
    .run(user_id, type, title || null, message, link || null, now());
}

const mailEnabled = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const mailFromName = process.env.MAIL_FROM_NAME || "SmartInventory";
const mailFromAddress = process.env.MAIL_FROM_ADDRESS || process.env.SMTP_USER || "";
const mailReplyTo = process.env.MAIL_REPLY_TO || mailFromAddress;
let mailer = null;

if(mailEnabled){
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    tls: {
      rejectUnauthorized: false
    }
  });
}

bootstrapAdmin();

function isEmail(value){
  if(!value) return false;
  return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(String(value).trim());
}

async function sendEmail({ to, subject, text, html }){
  if(!mailer || !to) return false;
  try{
    await mailer.sendMail({
      from: mailFromAddress ? `${mailFromName} <${mailFromAddress}>` : mailFromName,
      to,
      replyTo: mailReplyTo,
      subject,
      text,
      html
    });
    return true;
  }catch(err){
    return false;
  }
}

async function notifyOrderByEmail(order, template){
  if(!order) return;
  const contact = order.contact || order.delivery_phone || "";
  if(!isEmail(contact)) return;
  const trackUrl = `${APP_BASE_URL}/track.html?order=${order.id}&contact=${encodeURIComponent(contact)}`;
  const subject = template.subject.replace("{{orderId}}", order.id);
  const text = template.text
    .replace("{{orderId}}", order.id)
    .replace("{{status}}", order.status || "Order Placed")
    .replace("{{trackUrl}}", trackUrl)
    .replace("{{otp}}", order.otp_code || "");
  const html = template.html
    .replace("{{orderId}}", order.id)
    .replace("{{status}}", order.status || "Order Placed")
    .replace("{{trackUrl}}", trackUrl)
    .replace("{{otp}}", order.otp_code || "");
  await sendEmail({ to: contact, subject, text, html });
}

function saveWebAuthnChallenge(userId, type, challenge){
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  db.prepare("DELETE FROM webauthn_challenges WHERE user_id = ? AND type = ?").run(userId, type);
  db.prepare(`INSERT INTO webauthn_challenges (user_id,type,challenge,expires_at,created_at)
    VALUES (?,?,?,?,?)`).run(userId, type, challenge, expiresAt, now());
}

function getWebAuthnChallenge(userId, type){
  const row = db.prepare("SELECT * FROM webauthn_challenges WHERE user_id = ? AND type = ? ORDER BY created_at DESC LIMIT 1").get(userId, type);
  if(!row) return null;
  if(new Date(row.expires_at) < new Date()){
    db.prepare("DELETE FROM webauthn_challenges WHERE id = ?").run(row.id);
    return null;
  }
  return row;
}

function safeParseJson(raw, fallback){
  if(raw === null || raw === undefined || raw === "") return fallback;
  try{
    return JSON.parse(raw);
  }catch(err){
    return fallback;
  }
}

function buildTimelineEntry(status){
  return { step: status, time: now() };
}

function ensureTimeline(order, status){
  const timeline = safeParseJson(order.tracking_timeline, []);
  const last = timeline.length ? timeline[timeline.length - 1].step : null;
  if(last !== status){
    timeline.push(buildTimelineEntry(status));
  }
  return timeline;
}

function updateOrderStatus(orderId, status, extra = {}){
  const order = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(orderId);
  if(!order) return null;
  const timeline = ensureTimeline(order, status);
  const payload = {
    status,
    tracking_timeline: JSON.stringify(timeline),
    updated_at: now(),
    ...extra
  };
  const fields = Object.keys(payload);
  const setClause = fields.map(key => `${key} = ?`).join(", ");
  const values = fields.map(key => payload[key]);
  values.push(orderId);
  db.prepare(`UPDATE shopfront_orders SET ${setClause} WHERE id = ?`).run(...values);
  return db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(orderId);
}

function normalizeShopfrontOrder(row){
  if(!row) return null;
  const status = row.status === "pending" ? "Order Placed" : (row.status || "Order Placed");
  const timeline = safeParseJson(row.tracking_timeline, []);
  if(timeline.length === 0){
    timeline.push({ step: status, time: row.created_at || now() });
  }
  const paymentStatus = row.payment_status || (row.paid_at ? "Paid" : "Pending");
  return {
    ...row,
    status,
    payment_status: paymentStatus,
    items: safeParseJson(row.items_json, []),
    timeline
  };
}

function createShopfrontOrder({ customer_name, contact, items, branch_id, delivery_type, delivery_address, delivery_phone, payment_method, payment_reference, mpesa_account_id }){
  if(!items || !Array.isArray(items) || items.length === 0){
    return { error: "Items required" };
  }
  const branchId = Number(branch_id);
  if(!branchId) return { error: "Branch required" };
  if(!getBranchById(branchId)) return { error: "Branch not found" };

  let subtotal = 0;
  const detailed = [];
  for(const item of items){
    const product = db.prepare("SELECT * FROM products WHERE id = ?").get(item.product_id);
    if(!product) return { error: "Product not found" };
    if(product.branch_id && Number(product.branch_id) !== Number(branchId)){
      return { error: `Product ${product.name} is not in selected branch` };
    }
    const qty = Number(item.qty) || 0;
    if(qty <= 0) return { error: "Invalid quantity" };
    if(qty > Number(product.quantity)){
      return { error: `Not enough stock for ${product.name}` };
    }
    const override = db.prepare("SELECT price FROM product_prices WHERE product_id = ? AND branch_id = ?")
      .get(product.id, branchId);
    const price = override && override.price != null ? Number(override.price) : Number(product.price || 0);
    subtotal += price * qty;
    detailed.push({ product_id: product.id, name: product.name, qty, price, product });
  }

  if(detailed.length === 0) return { error: "No valid items" };

  const settings = getSettingsForBranch(branchId);
  const type = delivery_type === "door" ? "door" : "branch";
  if(type === "door" && !delivery_address){
    return { error: "Delivery address required" };
  }
  if(type === "door" && !(delivery_phone || contact)){
    return { error: "Delivery phone or contact required" };
  }
  const fee = type === "door" ? Number(settings.delivery_fee || 0) : 0;
  const total = subtotal + fee;
  const baseStatus = "Order Placed";
  const status = type === "door" ? "Ready for Delivery" : baseStatus;
  const method = String(payment_method || "").trim();
  const reference = String(payment_reference || "").trim();
  const methodLower = method.toLowerCase();
  let mpesaAccount = null;
  if(isMpesaMethod(method)){
    if(mpesa_account_id){
      mpesaAccount = getMpesaAccountById(Number(mpesa_account_id));
      if(!mpesaAccount || mpesaAccount.status !== "active"){
        return { error: "Selected M-Pesa account is not active" };
      }
      if(mpesaAccount.branch_id && Number(mpesaAccount.branch_id) !== Number(branchId)){
        return { error: "Selected M-Pesa account does not belong to this branch" };
      }
    }else{
      mpesaAccount = getDefaultMpesaAccountForBranch(branchId);
      if(!mpesaAccount){
        return { error: "No active M-Pesa account is configured for this branch" };
      }
    }
  }
  const requiresReference = methodLower && !(methodLower.includes("cash") || methodLower.includes("pay on") || methodLower.includes("delivery") || methodLower.includes("pickup"));
  if(requiresReference && !reference){
    return { error: "Payment reference required for selected payment method" };
  }
  const paidNow = Boolean(requiresReference && reference);
  let paymentStatus = paidNow ? "Paid" : "Pending";
  if(mpesaAccount && paidNow && !mpesaAccount.auto_confirm_payments){
    paymentStatus = "Verification Pending";
  }
  const paidAmount = paidNow ? total : null;
  const paidAt = paymentStatus === "Paid" ? now() : null;

  const timelineSteps = [buildTimelineEntry(baseStatus)];
  if(paymentStatus === "Paid"){
    timelineSteps.push(buildTimelineEntry("Payment Confirmed"));
  }
  if(status !== baseStatus){
    timelineSteps.push(buildTimelineEntry(status));
  }
  const timeline = JSON.stringify(timelineSteps);
  const otp = type === "door" ? String(Math.floor(1000 + Math.random() * 9000)) : null;
  const itemsPayload = detailed.map(({ product_id, name, qty, price }) => ({ product_id, name, qty, price }));
  const insertOrder = db.prepare(`INSERT INTO shopfront_orders (customer_name,contact,items_json,subtotal,total,branch_id,status,payment_method,payment_status,payment_reference,paid_amount,paid_at,delivery_type,delivery_address,delivery_phone,delivery_fee,tracking_timeline,otp_code,stock_committed,mpesa_account_id,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const updateProduct = db.prepare("UPDATE products SET quantity=?, updated_at=? WHERE id=?");
  const insertMove = db.prepare(`INSERT INTO inventory_movements (product_id,product_name,type,qty,reference,note,user_id,user_name,branch_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);

  let orderId = null;
  try{
    const trx = db.transaction(() => {
      const info = insertOrder.run(
        customer_name || "",
        contact || "",
        JSON.stringify(itemsPayload),
        subtotal,
        total,
        branchId,
        status,
        method || null,
        paymentStatus,
        reference || null,
        paidAmount,
        paidAt,
        type,
        delivery_address || "",
        delivery_phone || contact || "",
        fee,
        timeline,
        otp,
        1,
        mpesaAccount ? mpesaAccount.id : null,
        now(),
        now()
      );

      detailed.forEach(item => {
        const newQty = Number(item.product.quantity) - item.qty;
        updateProduct.run(newQty, now(), item.product.id);
        insertMove.run(
          item.product.id,
          item.product.name,
          "RESERVE",
          item.qty,
          `ORDER#${info.lastInsertRowid}`,
          "Online order",
          null,
          "Shopfront",
          branchId,
          now()
        );
      });
      return info.lastInsertRowid;
    });
    orderId = trx();
  }catch(err){
    return { error: err.message || "Unable to place order" };
  }

  if(mpesaAccount){
    recordMpesaTransaction({
      user_id: mpesaAccount.user_id,
      account_id: mpesaAccount.id,
      branch_id: branchId,
      order_id: orderId,
      phone_number: delivery_phone || contact || mpesaAccount.phone_number || "",
      amount: total,
      reference,
      status: paymentStatus === "Paid" ? "success" : (paymentStatus === "Verification Pending" ? "pending_verification" : "pending"),
      request_payload: {
        customer_name,
        branch_id: branchId,
        delivery_type: type,
        payment_method: method
      }
    });
  }

  return {
    id: orderId,
    status,
    delivery_type: type,
    otp_code: otp,
    total,
    delivery_fee: fee,
    payment_status: paymentStatus,
    mpesa_account: mpesaAccount ? {
      id: mpesaAccount.id,
      account_name: mpesaAccount.account_name,
      business_type: mpesaAccount.business_type,
      shortcode: mpesaAccount.shortcode,
      phone_number: mpesaAccount.phone_number || "",
      account_reference: mpesaAccount.account_reference || "Order Payment",
      transaction_description: mpesaAccount.transaction_description || "Customer order payment"
    } : null
  };
}

function getReorderThreshold(product){
  const minStock = Number(product.min_stock);
  if(Number.isFinite(minStock)) return minStock;
  const reorder = Number(product.reorder_level);
  return Number.isFinite(reorder) ? reorder : 10;
}

function notifyUsersByRoles(roles, payload, branchId){
  if(!roles || roles.length === 0) return;
  const params = [];
  let where = "WHERE role IN (" + roles.map(()=>"?").join(",") + ")";
  params.push(...roles);
  if(branchId){
    where += " AND branch_id = ?";
    params.push(branchId);
  }
  const users = db.prepare(`SELECT id FROM users ${where}`).all(...params);
  users.forEach(u => createNotification({ ...payload, user_id: u.id }));
}

function getBroadcastThread(){
  let thread = db.prepare("SELECT * FROM message_threads WHERE type = 'broadcast' LIMIT 1").get();
  if(!thread){
    const info = db.prepare(`INSERT INTO message_threads (name,type,created_by,branch_id,created_at)
      VALUES (?,?,?,?,?)`).run("System Broadcasts", "broadcast", null, null, now());
    thread = { id: info.lastInsertRowid, name: "System Broadcasts", type: "broadcast" };
  }
  return thread;
}

// ===== Setup =====
app.get("/api/setup/status", (req, res) => {
  const row = db.prepare("SELECT COUNT(*) as count FROM users").get();
  res.json({ needsSetup: row.count === 0 });
});

app.post("/api/setup", (req, res) => {
  const row = db.prepare("SELECT COUNT(*) as count FROM users").get();
  if(row.count > 0) return sendError(res, 400, "Setup already completed");
  const { name, email, password } = req.body || {};
  if(!name || !email || !password) return sendError(res, 400, "Missing fields");
  if(!isStrongPassword(password)){
    return sendError(res, 400, "Password must be at least 8 chars with upper, lower, and number");
  }

  const branch = db.prepare("SELECT id FROM branches ORDER BY id ASC LIMIT 1").get();
  if(!branch) return sendError(res, 400, "No branch available");
  const hash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare(`INSERT INTO users (name,email,password_hash,role,status,created_at,last_login,branch_id,password_changed_at)
    VALUES (?,?,?,?,?,?,?,?,?)`);
  stmt.run(name, email, hash, "admin", "active", now(), "-", branch.id, now());
  res.json({ success: true });
});

// ===== Auth =====
app.post("/api/auth/reset/request", async (req, res) => {
  const { email } = req.body || {};
  const normalized = String(email || "").trim().toLowerCase();
  if(!isEmail(normalized)) return sendError(res, 400, "Valid email required");
  if(!mailer) return sendError(res, 500, "Email service not configured");

  const user = db.prepare("SELECT id,name,email FROM users WHERE LOWER(email) = ?").get(normalized);
  if(!user){
    return res.json({ success: true });
  }

  const code = generateResetCode();
  const codeHash = bcrypt.hashSync(code, 8);
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  db.prepare("DELETE FROM password_resets WHERE user_id = ?").run(user.id);
  db.prepare(`INSERT INTO password_resets (user_id,code_hash,expires_at,used,created_at)
    VALUES (?,?,?,?,?)`).run(user.id, codeHash, expiresAt, 0, now());

  const subject = "Password Reset Code";
  const text = `Hello ${user.name || "User"}, your password reset code is ${code}. It expires in 15 minutes.`;
  const html = `<p>Hello ${user.name || "User"},</p><p>Your password reset code is <strong>${code}</strong>. It expires in 15 minutes.</p>`;
  const sent = await sendEmail({ to: user.email, subject, text, html });
  if(!sent) return sendError(res, 500, "Unable to send email");

  res.json({ success: true });
});

app.post("/api/auth/reset/confirm", (req, res) => {
  const { email, code, new_password } = req.body || {};
  const normalized = String(email || "").trim().toLowerCase();
  if(!isEmail(normalized)) return sendError(res, 400, "Valid email required");
  if(!code || !new_password) return sendError(res, 400, "Code and new password required");
  if(!isStrongPassword(new_password)) return sendError(res, 400, "Password must be at least 8 characters with upper, lower, and number");

  const user = db.prepare("SELECT id,name,email FROM users WHERE LOWER(email) = ?").get(normalized);
  if(!user) return sendError(res, 404, "Account not found");

  const reset = db.prepare("SELECT * FROM password_resets WHERE user_id = ? AND used = 0 ORDER BY created_at DESC LIMIT 1").get(user.id);
  if(!reset) return sendError(res, 400, "Reset code not found");
  if(new Date(reset.expires_at) < new Date()) return sendError(res, 400, "Reset code expired");
  const ok = bcrypt.compareSync(String(code), reset.code_hash);
  if(!ok) return sendError(res, 400, "Invalid reset code");

  const hash = bcrypt.hashSync(String(new_password), 10);
  db.prepare("UPDATE users SET password_hash = ?, password_changed_at = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?")
    .run(hash, now(), user.id);
  db.prepare("UPDATE password_resets SET used = 1 WHERE id = ?").run(reset.id);
  res.json({ success: true });
});

app.post("/api/auth/login", (req, res) => {
  const { identifier, email, username, staff_id, password, remember_me } = req.body || {};
  const lookup = identifier || email || username || staff_id;
  if(!lookup || !password) return sendError(res, 400, "Login ID and password required");

  const user = db.prepare("SELECT * FROM users WHERE email = ? OR username = ? OR staff_id = ?").get(lookup, lookup, lookup);
  if(!user) return sendError(res, 401, "Invalid credentials");
  if(user.status && user.status.toLowerCase() === "inactive") return sendError(res, 403, "Account inactive");
  if(user.status && user.status.toLowerCase() === "pending") return sendError(res, 403, "Account pending approval");
  if(user.locked_until){
    const lockedUntil = new Date(user.locked_until);
    if(!isNaN(lockedUntil) && lockedUntil > new Date()){
      return sendError(res, 403, "Account locked. Try again later.");
    }
  }

  const ok = bcrypt.compareSync(password, user.password_hash);
  if(!ok){
    const attempts = (Number(user.failed_login_attempts) || 0) + 1;
    if(attempts >= 5){
      const lockUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      db.prepare("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?").run(0, lockUntil, user.id);
      return sendError(res, 403, "Account locked for 15 minutes");
    }
    db.prepare("UPDATE users SET failed_login_attempts = ? WHERE id = ?").run(attempts, user.id);
    return sendError(res, 401, "Invalid credentials");
  }

  db.prepare("UPDATE users SET last_login = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?").run(now(), user.id);

  // Auto clock-in on login (if no open attendance record today)
  const openAttendance = db.prepare("SELECT id FROM attendance WHERE user_id = ? AND date = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1")
    .get(user.id, today());
  if(!openAttendance){
    db.prepare(`INSERT INTO attendance (user_id,branch_id,date,clock_in,method,created_at)
      VALUES (?,?,?,?,?,?)`)
      .run(user.id, user.branch_id || null, today(), now(), "login", now());
    logActivity(user, "clock_in", "attendance", null, "Auto clock-in on login", user.branch_id);
  }

  const remember = remember_me === true || remember_me === "true" || remember_me === 1 || remember_me === "1";
  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email, role: user.role, branch_id: user.branch_id },
    JWT_SECRET,
    { expiresIn: remember ? "30d" : "12h" }
  );
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role, branch_id: user.branch_id, username: user.username, staff_id: user.staff_id }
  });

  logActivity(user, "login", "auth", null, "User login", user.branch_id);
});

app.post("/api/auth/vendor-register", (req, res) => {
  const { name, email, password, role, branch_id, username, phone } = req.body || {};
  const normalizedRole = String(role || "").toLowerCase();
  if(!name || !email || !password || !normalizedRole) return sendError(res, 400, "Missing fields");
  if(!isVendorRole(normalizedRole)) return sendError(res, 400, "Invalid vendor role");
  if(!phone) return sendError(res, 400, "Phone required");
  if(!isStrongPassword(password)) return sendError(res, 400, "Password must be at least 8 chars with upper, lower, and number");

  const branchId = Number(branch_id);
  if(!branchId || !getBranchById(branchId)) return sendError(res, 400, "Valid branch required");

  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if(exists) return sendError(res, 400, "Email already exists");

  let finalUsername = username ? String(username).trim() : generateUniqueUsername(email.split("@")[0]);
  if(finalUsername){
    const uExists = db.prepare("SELECT id FROM users WHERE username = ?").get(finalUsername);
    if(uExists) finalUsername = generateUniqueUsername(finalUsername);
  }

  const hash = bcrypt.hashSync(password, 10);
  const supplierName = `${name} (${normalizedRole})`;
  let supplierId = null;
  const existingSupplier = db.prepare("SELECT id FROM suppliers WHERE name = ?").get(supplierName);
  if(existingSupplier){
    supplierId = existingSupplier.id;
  }else{
    const supplierInfo = db.prepare(`INSERT INTO suppliers (name,contact,phone,email,address,lead_time,status,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(supplierName, name, phone, email, "", null, "active", now(), now());
    supplierId = supplierInfo.lastInsertRowid;
  }

  const stmt = db.prepare(`INSERT INTO users (name,email,phone,password_hash,role,status,created_at,last_login,branch_id,username,password_changed_at,supplier_id)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
  const info = stmt.run(name, email, String(phone).trim(), hash, normalizedRole, "pending", now(), "-", branchId, finalUsername, now(), supplierId);

  notifyUsersByRoles(
    ["admin"],
    { type: "Users", title: "Vendor Approval", message: `${name} registered as ${normalizedRole}. Approval required.`, link: "users.html" },
    branchId
  );

  res.json({ success: true, user_id: info.lastInsertRowid });
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.post("/api/auth/logout", authMiddleware, (req, res) => {
  const open = db.prepare("SELECT * FROM attendance WHERE user_id = ? AND date = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1")
    .get(req.user.id, today());
  if(open){
    const clockOut = now();
    const hours = (new Date(clockOut) - new Date(open.clock_in)) / 3600000;
    const status = hours > 8 ? "overtime" : open.status;
    db.prepare("UPDATE attendance SET clock_out = ?, total_hours = ?, status = ? WHERE id = ?")
      .run(clockOut, Math.max(0, Number(hours.toFixed(2))), status, open.id);
    logActivity(req.user, "clock_out", "attendance", open.id, "Auto clock-out on logout", req.user.branch_id);
  }
  logActivity(req.user, "logout", "auth", null, "User logout", req.user.branch_id);
  res.json({ success: true });
});

// ===== Settings =====
app.get("/api/settings", authMiddleware, (req, res) => {
  const branchId = resolveBranchId(req) || 0;
  const settings = getSettingsForBranch(branchId);
  res.json(settings);
});

app.put("/api/settings", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const branchId = resolveBranchIdFromBody(req) || 0;
  const payload = req.body && req.body.settings;
  if(!payload || typeof payload !== "object"){
    return sendError(res, 400, "Settings payload required");
  }
  saveSettings(payload, branchId);
  logActivity(req.user, "settings_update", "settings", null, `Updated settings (branch ${branchId || "global"})`, branchId || null);
  res.json({ success: true });
});

app.get("/api/mpesa/accounts", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const scopeAll = req.user.role === "admin" && String(req.query.scope || "") === "all";
  let rows = [];

  if(scopeAll){
    if(branchId){
      rows = db.prepare(`
        SELECT a.*, u.name as user_name, b.name as branch_name
        FROM mpesa_accounts a
        LEFT JOIN users u ON u.id = a.user_id
        LEFT JOIN branches b ON b.id = a.branch_id
        WHERE COALESCE(a.branch_id, 0) IN (0, ?)
        ORDER BY a.is_default DESC, a.updated_at DESC, a.id DESC
      `).all(branchId);
    }else{
      rows = db.prepare(`
        SELECT a.*, u.name as user_name, b.name as branch_name
        FROM mpesa_accounts a
        LEFT JOIN users u ON u.id = a.user_id
        LEFT JOIN branches b ON b.id = a.branch_id
        ORDER BY a.is_default DESC, a.updated_at DESC, a.id DESC
      `).all();
    }
  }else if(branchId){
    rows = db.prepare(`
      SELECT a.*, u.name as user_name, b.name as branch_name
      FROM mpesa_accounts a
      LEFT JOIN users u ON u.id = a.user_id
      LEFT JOIN branches b ON b.id = a.branch_id
      WHERE a.user_id = ? AND COALESCE(a.branch_id, 0) IN (0, ?)
      ORDER BY a.is_default DESC, a.updated_at DESC, a.id DESC
    `).all(req.user.id, branchId);
  }else{
    rows = db.prepare(`
      SELECT a.*, u.name as user_name, b.name as branch_name
      FROM mpesa_accounts a
      LEFT JOIN users u ON u.id = a.user_id
      LEFT JOIN branches b ON b.id = a.branch_id
      WHERE a.user_id = ?
      ORDER BY a.is_default DESC, a.updated_at DESC, a.id DESC
    `).all(req.user.id);
  }

  res.json(rows.map(row => ({
    ...sanitizeMpesaAccount(row),
    config_ready: !!(decryptSecret(row.consumer_key) && decryptSecret(row.consumer_secret) && decryptSecret(row.passkey))
  })));
});

app.post("/api/mpesa/accounts", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const branchId = resolveBranchIdFromBody(req) || 0;
  const {
    account_name,
    business_type,
    shortcode,
    consumer_key,
    consumer_secret,
    passkey,
    environment,
    phone_number,
    account_reference,
    transaction_description,
    enable_stk_push,
    enable_c2b,
    currency,
    auto_confirm_payments,
    is_default,
    status
  } = req.body || {};

  if(!account_name || !shortcode){
    return sendError(res, 400, "Account name and shortcode are required");
  }

  const encryptedKey = encryptSecret(consumer_key);
  const encryptedSecret = encryptSecret(consumer_secret);
  const encryptedPasskey = encryptSecret(passkey);
  const configReady = !!(encryptedKey && encryptedSecret && encryptedPasskey);
  const finalStatus = status === "inactive" || !configReady ? "inactive" : "active";
  const info = db.prepare(`
    INSERT INTO mpesa_accounts (
      user_id, branch_id, account_name, business_type, shortcode,
      consumer_key, consumer_secret, passkey, environment, phone_number,
      account_reference, transaction_description, enable_stk_push, enable_c2b,
      currency, auto_confirm_payments, is_default, status, created_at, updated_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    req.user.id,
    branchId || null,
    String(account_name).trim(),
    normalizeMpesaBusinessType(business_type),
    String(shortcode).trim(),
    encryptedKey,
    encryptedSecret,
    encryptedPasskey,
    normalizeMpesaEnvironment(environment),
    String(phone_number || "").trim(),
    String(account_reference || "Order Payment").trim(),
    String(transaction_description || "Customer order payment").trim(),
    enable_stk_push === false || enable_stk_push === "false" ? 0 : 1,
    enable_c2b === true || enable_c2b === "true" ? 1 : 0,
    String(currency || "KES").trim().toUpperCase() || "KES",
    auto_confirm_payments === true || auto_confirm_payments === "true" ? 1 : 0,
    0,
    finalStatus,
    now(),
    now()
  );

  const urls = buildMpesaUrls(info.lastInsertRowid);
  db.prepare(`
    UPDATE mpesa_accounts
    SET callback_url = ?, validation_url = ?, confirmation_url = ?, updated_at = ?
    WHERE id = ?
  `).run(urls.callback_url, urls.validation_url, urls.confirmation_url, now(), info.lastInsertRowid);

  const created = getMpesaAccountById(info.lastInsertRowid);
  const existingCount = db.prepare("SELECT COUNT(*) as count FROM mpesa_accounts WHERE user_id = ? AND COALESCE(branch_id, 0) = ?")
    .get(req.user.id, branchId || 0);
  if((is_default === true || is_default === "true") || Number(existingCount.count) === 1){
    setMpesaDefaultAccount(req.user.id, branchId || 0, info.lastInsertRowid);
  }

  logActivity(req.user, "mpesa_account_create", "mpesa_accounts", info.lastInsertRowid, `M-Pesa account ${account_name} created`, branchId || null);
  res.json({
    success: true,
    account: {
      ...sanitizeMpesaAccount(getMpesaAccountById(info.lastInsertRowid)),
      config_ready: configReady
    }
  });
});

app.put("/api/mpesa/accounts/:id", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const accountId = Number(req.params.id);
  const existing = getMpesaAccountById(accountId);
  if(!existing) return sendError(res, 404, "M-Pesa account not found");
  if(!canManageMpesaAccount(req.user, existing)) return sendError(res, 403, "Forbidden");

  const {
    account_name,
    business_type,
    shortcode,
    consumer_key,
    consumer_secret,
    passkey,
    environment,
    phone_number,
    account_reference,
    transaction_description,
    enable_stk_push,
    enable_c2b,
    currency,
    auto_confirm_payments,
    is_default,
    status
  } = req.body || {};

  const encryptedKey = String(consumer_key || "").trim() ? encryptSecret(consumer_key) : existing.consumer_key;
  const encryptedSecret = String(consumer_secret || "").trim() ? encryptSecret(consumer_secret) : existing.consumer_secret;
  const encryptedPasskey = String(passkey || "").trim() ? encryptSecret(passkey) : existing.passkey;
  const configReady = !!(decryptSecret(encryptedKey) && decryptSecret(encryptedSecret) && decryptSecret(encryptedPasskey));
  const nextStatus = status ? String(status) : existing.status;
  const finalStatus = nextStatus === "inactive" || !configReady ? "inactive" : "active";

  db.prepare(`
    UPDATE mpesa_accounts
    SET account_name = ?, business_type = ?, shortcode = ?, consumer_key = ?, consumer_secret = ?, passkey = ?,
        environment = ?, phone_number = ?, account_reference = ?, transaction_description = ?,
        enable_stk_push = ?, enable_c2b = ?, currency = ?, auto_confirm_payments = ?, status = ?, updated_at = ?
    WHERE id = ?
  `).run(
    String(account_name || existing.account_name).trim(),
    normalizeMpesaBusinessType(business_type || existing.business_type),
    String(shortcode || existing.shortcode).trim(),
    encryptedKey,
    encryptedSecret,
    encryptedPasskey,
    normalizeMpesaEnvironment(environment || existing.environment),
    String(phone_number ?? existing.phone_number ?? "").trim(),
    String(account_reference ?? existing.account_reference ?? "Order Payment").trim(),
    String(transaction_description ?? existing.transaction_description ?? "Customer order payment").trim(),
    enable_stk_push === undefined ? Number(existing.enable_stk_push) : ((enable_stk_push === true || enable_stk_push === "true") ? 1 : 0),
    enable_c2b === undefined ? Number(existing.enable_c2b) : ((enable_c2b === true || enable_c2b === "true") ? 1 : 0),
    String(currency || existing.currency || "KES").trim().toUpperCase() || "KES",
    auto_confirm_payments === undefined ? Number(existing.auto_confirm_payments) : ((auto_confirm_payments === true || auto_confirm_payments === "true") ? 1 : 0),
    finalStatus,
    now(),
    accountId
  );

  if(is_default === true || is_default === "true"){
    setMpesaDefaultAccount(existing.user_id, existing.branch_id || 0, accountId);
  }

  logActivity(req.user, "mpesa_account_update", "mpesa_accounts", accountId, `M-Pesa account ${accountId} updated`, existing.branch_id || null);
  res.json({
    success: true,
    account: {
      ...sanitizeMpesaAccount(getMpesaAccountById(accountId)),
      config_ready: configReady
    }
  });
});

app.post("/api/mpesa/accounts/:id/default", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const accountId = Number(req.params.id);
  const account = getMpesaAccountById(accountId);
  if(!account) return sendError(res, 404, "M-Pesa account not found");
  if(!canManageMpesaAccount(req.user, account)) return sendError(res, 403, "Forbidden");
  setMpesaDefaultAccount(account.user_id, account.branch_id || 0, accountId);
  logActivity(req.user, "mpesa_account_default", "mpesa_accounts", accountId, `Default account set to ${account.account_name}`, account.branch_id || null);
  res.json({ success: true });
});

app.delete("/api/mpesa/accounts/:id", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const accountId = Number(req.params.id);
  const account = getMpesaAccountById(accountId);
  if(!account) return sendError(res, 404, "M-Pesa account not found");
  if(!canManageMpesaAccount(req.user, account)) return sendError(res, 403, "Forbidden");
  db.prepare("DELETE FROM mpesa_accounts WHERE id = ?").run(accountId);
  logActivity(req.user, "mpesa_account_delete", "mpesa_accounts", accountId, `Deleted M-Pesa account ${account.account_name}`, account.branch_id || null);
  res.json({ success: true });
});

app.get("/api/mpesa/transactions", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const scopeAll = req.user.role === "admin" && String(req.query.scope || "") === "all";
  const baseQuery = `
    SELECT t.*, a.account_name, a.shortcode, a.business_type, b.name as branch_name, u.name as user_name
    FROM mpesa_transactions t
    LEFT JOIN mpesa_accounts a ON a.id = t.account_id
    LEFT JOIN branches b ON b.id = t.branch_id
    LEFT JOIN users u ON u.id = t.user_id
  `;
  let rows;
  if(scopeAll && branchId){
    rows = db.prepare(`${baseQuery} WHERE COALESCE(t.branch_id, 0) IN (0, ?) ORDER BY t.created_at DESC LIMIT 200`).all(branchId);
  }else if(scopeAll){
    rows = db.prepare(`${baseQuery} ORDER BY t.created_at DESC LIMIT 200`).all();
  }else if(branchId){
    rows = db.prepare(`${baseQuery} WHERE t.user_id = ? AND COALESCE(t.branch_id, 0) IN (0, ?) ORDER BY t.created_at DESC LIMIT 200`).all(req.user.id, branchId);
  }else{
    rows = db.prepare(`${baseQuery} WHERE t.user_id = ? ORDER BY t.created_at DESC LIMIT 200`).all(req.user.id);
  }
  res.json(rows);
});

app.post("/api/mpesa/accounts/:id/callback", (req, res) => {
  const accountId = Number(req.params.id);
  const account = getMpesaAccountById(accountId);
  if(!account) return sendError(res, 404, "M-Pesa account not found");

  const payload = req.body || {};
  const callback = payload.Body && payload.Body.stkCallback ? payload.Body.stkCallback : null;
  const metadataItems = callback && callback.CallbackMetadata && Array.isArray(callback.CallbackMetadata.Item)
    ? callback.CallbackMetadata.Item
    : [];
  const meta = {};
  metadataItems.forEach(item => {
    if(item && item.Name) meta[item.Name] = item.Value;
  });

  recordMpesaTransaction({
    user_id: account.user_id,
    account_id: accountId,
    branch_id: account.branch_id || null,
    phone_number: meta.PhoneNumber || "",
    amount: meta.Amount || null,
    reference: meta.AccountReference || "",
    mpesa_receipt: meta.MpesaReceiptNumber || "",
    status: callback && Number(callback.ResultCode) === 0 ? "success" : "failed",
    result_code: callback ? String(callback.ResultCode) : null,
    result_desc: callback ? String(callback.ResultDesc || "") : "STK callback received",
    response_payload: payload
  });

  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

app.post("/api/mpesa/accounts/:id/validation", (req, res) => {
  const accountId = Number(req.params.id);
  const account = getMpesaAccountById(accountId);
  if(!account) return sendError(res, 404, "M-Pesa account not found");
  recordMpesaTransaction({
    user_id: account.user_id,
    account_id: accountId,
    branch_id: account.branch_id || null,
    phone_number: req.body && req.body.MSISDN,
    amount: req.body && req.body.TransAmount,
    reference: req.body && req.body.BillRefNumber,
    mpesa_receipt: req.body && req.body.TransID,
    status: "validation_received",
    response_payload: req.body || {}
  });
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

app.post("/api/mpesa/accounts/:id/confirmation", (req, res) => {
  const accountId = Number(req.params.id);
  const account = getMpesaAccountById(accountId);
  if(!account) return sendError(res, 404, "M-Pesa account not found");
  recordMpesaTransaction({
    user_id: account.user_id,
    account_id: accountId,
    branch_id: account.branch_id || null,
    phone_number: req.body && req.body.MSISDN,
    amount: req.body && req.body.TransAmount,
    reference: req.body && req.body.BillRefNumber,
    mpesa_receipt: req.body && req.body.TransID,
    status: "confirmed",
    response_payload: req.body || {}
  });
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
});

app.get("/api/legal/terms", (req, res) => {
  const branchId = resolveLegalBranchId(req);
  const settings = getSettingsForBranch(branchId);
  res.type("html").send(settings.terms_conditions || DEFAULT_SETTINGS.terms_conditions);
});

app.get("/api/legal/privacy", (req, res) => {
  const branchId = resolveLegalBranchId(req);
  const settings = getSettingsForBranch(branchId);
  res.type("html").send(settings.privacy_policy || DEFAULT_SETTINGS.privacy_policy);
});

app.post("/api/settings/reset", authMiddleware, requireRole(["admin"]), (req, res) => {
  const { mode, confirm } = req.body || {};
  if(confirm !== "RESET") return sendError(res, 400, "Confirmation required");
  const resetMode = mode || "transactions";

  const trx = db.transaction(() => {
    if(resetMode === "transactions"){
      db.prepare("DELETE FROM sale_items").run();
      db.prepare("DELETE FROM sales").run();
      db.prepare("DELETE FROM returns").run();
      db.prepare("DELETE FROM return_items").run();
      db.prepare("DELETE FROM inventory_movements").run();
      db.prepare("DELETE FROM purchase_orders").run();
      db.prepare("DELETE FROM shopfront_orders").run();
    }else if(resetMode === "full"){
      db.prepare("DELETE FROM sale_items").run();
      db.prepare("DELETE FROM sales").run();
      db.prepare("DELETE FROM returns").run();
      db.prepare("DELETE FROM return_items").run();
      db.prepare("DELETE FROM inventory_movements").run();
      db.prepare("DELETE FROM purchase_orders").run();
      db.prepare("DELETE FROM shopfront_orders").run();
      db.prepare("DELETE FROM products").run();
      db.prepare("DELETE FROM suppliers").run();
      db.prepare("DELETE FROM customers").run();
      db.prepare("DELETE FROM product_prices").run();
    }else{
      throw new Error("Unsupported reset mode");
    }
    db.prepare("DELETE FROM activity_logs").run();
    db.prepare("DELETE FROM feedback").run();
  });

  try{
    trx();
  }catch(err){
    return sendError(res, 400, err.message || "Reset failed");
  }
  logActivity(req.user, "reset", "settings", null, `Reset mode: ${resetMode}`, req.user.branch_id);
  res.json({ success: true });
});

// ===== DASHBOARD SUMMARY (for hamburger menu notifications) =====
app.get("/api/dashboard/summary", authMiddleware, (req, res) => {
  try {
    const branchId = resolveBranchId(req);
    const userRole = req.user.role;
    const userId = req.user.id;

    // Build branch filter for queries
    const branchFilter = branchId ? ` AND branch_id = ${branchId}` : '';

    // Low stock products (quantity <= reorder_level)
    const lowStockQuery = `
      SELECT COUNT(*) as count FROM products
      WHERE quantity <= COALESCE(reorder_level, 0) AND is_published = 1 ${branchFilter}
    `;
    const lowStock = db.prepare(lowStockQuery).get().count;

    // Pending orders (recent sales as proxy for pending orders)
    const pendingOrdersQuery = `
      SELECT COUNT(*) as count FROM sales
      WHERE created_at >= date('now', '-30 days') ${branchFilter}
    `;
    const pendingOrders = db.prepare(pendingOrdersQuery).get().count;

    // Unresolved feedback
    const unresolvedFeedback = db.prepare(`
      SELECT COUNT(*) as count FROM feedback
      WHERE status = 'pending' ${branchFilter}
    `).get().count;

    // Open requests
    const openRequests = db.prepare(`
      SELECT COUNT(*) as count FROM requests
      WHERE status = 'pending' ${branchFilter}
    `).get().count;

    // Unread messages (for current user)
    const unreadMessages = db.prepare(`
      SELECT COUNT(*) as count FROM messages m
      LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id = ?
      WHERE mr.read_at IS NULL AND m.sender_id != ?
      AND m.thread_id IN (
        SELECT thread_id FROM message_participants WHERE user_id = ?
      )
    `).get(userId, userId, userId).count;

    const unreadNotifications = db.prepare(`
      SELECT COUNT(*) as count FROM notifications
      WHERE user_id = ? AND status = 'unread'
    `).get(userId).count;

    // Absent today (for admin/manager/supervisor)
    let absentToday = 0;
    if(['admin','manager','supervisor'].includes(userRole)){
      const absentBranchFilter = branchId ? ` AND u.branch_id = ${branchId}` : "";
      absentToday = db.prepare(`
        SELECT COUNT(DISTINCT u.id) as count FROM users u
        LEFT JOIN attendance a ON u.id = a.user_id AND a.date = ?
        WHERE u.status = 'active' AND u.role NOT IN ('admin','supplier','seller','retailer','wholesaler')
        AND a.id IS NULL ${absentBranchFilter}
      `).get(today()).count;
    }

    res.json({
      lowStock: lowStock || 0,
      pendingOrders: pendingOrders || 0,
      unresolvedFeedback: unresolvedFeedback || 0,
      openRequests: openRequests || 0,
      unreadMessages: unreadMessages || 0,
      unreadNotifications: unreadNotifications || 0,
      absentToday: absentToday || 0
    });

  } catch (err) {
    console.error('Dashboard summary error:', err);
    res.status(500).json({ error: 'Failed to load dashboard summary' });
  }
});

// ===== Users =====
app.get("/api/users", authMiddleware, requireRole(["admin"]), (req, res) => {
  const rows = db.prepare(`
    SELECT u.id,u.name,u.email,u.phone,u.username,u.staff_id,u.role,u.status,u.created_at,u.last_login,u.branch_id,u.supplier_id,
           b.name as branch_name
    FROM users u
    LEFT JOIN branches b ON u.branch_id = b.id
    ORDER BY u.id DESC
  `).all();
  res.json(rows);
});

app.post("/api/users", authMiddleware, requireRole(["admin"]), (req, res) => {
  const { name, email, phone, role, status, password, branch_id, username, staff_id } = req.body || {};
  if(!name || !email || !role || !password) return sendError(res, 400, "Missing fields");
  if(!username && !staff_id) return sendError(res, 400, "Username or staff ID required");
  if(isVendorRole(role) && !phone) return sendError(res, 400, "Phone required for vendor accounts");
  if(!isStrongPassword(password)){
    return sendError(res, 400, "Password must be at least 8 chars with upper, lower, and number");
  }

  const branchId = branch_id ? Number(branch_id) : resolveBranchIdFromBody(req);
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");

  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if(exists) return sendError(res, 400, "Email already exists");
  if(username){
    const uExists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
    if(uExists) return sendError(res, 400, "Username already exists");
  }
  if(staff_id){
    const sExists = db.prepare("SELECT id FROM users WHERE staff_id = ?").get(staff_id);
    if(sExists) return sendError(res, 400, "Staff ID already exists");
  }

  const hash = bcrypt.hashSync(password, 10);
  let supplierId = null;
  if(isVendorRole(role)){
    const supplierName = `${name} (${String(role).toLowerCase()})`;
    const existingSupplier = db.prepare("SELECT id FROM suppliers WHERE email = ? OR name = ?").get(email, supplierName);
    if(existingSupplier){
      supplierId = existingSupplier.id;
      db.prepare(`UPDATE suppliers SET name=?, contact=?, phone=?, email=?, updated_at=? WHERE id=?`)
        .run(supplierName, name, String(phone || "").trim(), email, now(), supplierId);
    }else{
      const supplierInfo = db.prepare(`INSERT INTO suppliers (name,contact,phone,email,address,lead_time,status,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(supplierName, name, String(phone || "").trim(), email, "", null, "active", now(), now());
      supplierId = supplierInfo.lastInsertRowid;
    }
  }

  const stmt = db.prepare(`INSERT INTO users (name,email,phone,password_hash,role,status,created_at,last_login,branch_id,username,staff_id,password_changed_at,supplier_id)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const info = stmt.run(
    name,
    email,
    phone ? String(phone).trim() : "",
    hash,
    role,
    status || "active",
    now(),
    "-",
    branchId,
    username || null,
    staff_id || null,
    now(),
    supplierId
  );
  logActivity(req.user, "user_create", "users", info.lastInsertRowid, `User ${name}`, branchId);
  res.json({ id: info.lastInsertRowid });
});

app.put("/api/users/:id", authMiddleware, requireRole(["admin"]), (req, res) => {
  const id = Number(req.params.id);
  const { name, email, phone, role, status, password, branch_id, username, staff_id, supplier_id } = req.body || {};

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if(!user) return sendError(res, 404, "User not found");

  // PROTECTION: Prevent modifying locked admin accounts
  if(user.admin_locked){
    return sendError(res, 403, "This admin account is locked and cannot be modified. It is permanent after deployment.");
  }

  // prevent removing last admin
  if(user.role === "admin" && role && role !== "admin"){
    const admins = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get();
    if(admins.count <= 1) return sendError(res, 400, "At least one admin required");
  }

  const newName = name || user.name;
  const newEmail = email || user.email;
  const newRole = role || user.role;
  const newStatus = status || user.status;
  if(password && !isStrongPassword(password)){
    return sendError(res, 400, "Password must be at least 8 chars with upper, lower, and number");
  }
  const newHash = password ? bcrypt.hashSync(password, 10) : user.password_hash;
  const passwordChangedAt = password ? now() : user.password_changed_at;
  const newBranch = branch_id !== undefined && branch_id !== null && branch_id !== "" ? Number(branch_id) : user.branch_id;
  if(newBranch && !getBranchById(newBranch)) return sendError(res, 400, "Branch not found");
  const newPhone = phone !== undefined ? String(phone).trim() : (user.phone || "");
  const newUsername = username !== undefined ? username : user.username;
  const newStaffId = staff_id !== undefined ? staff_id : user.staff_id;
  let newSupplierId = supplier_id !== undefined && supplier_id !== null && supplier_id !== "" ? Number(supplier_id) : user.supplier_id;
  if(newUsername && newUsername !== user.username){
    const uExists = db.prepare("SELECT id FROM users WHERE username = ? AND id != ?").get(newUsername, id);
    if(uExists) return sendError(res, 400, "Username already exists");
  }
  if(newStaffId && newStaffId !== user.staff_id){
    const sExists = db.prepare("SELECT id FROM users WHERE staff_id = ? AND id != ?").get(newStaffId, id);
    if(sExists) return sendError(res, 400, "Staff ID already exists");
  }
  if(isVendorRole(newRole) && !newPhone){
    return sendError(res, 400, "Phone required for vendor accounts");
  }

  if(isVendorRole(newRole)){
    const supplierName = `${newName} (${String(newRole).toLowerCase()})`;
    if(newSupplierId){
      db.prepare(`UPDATE suppliers SET name=?, contact=?, phone=?, email=?, updated_at=? WHERE id=?`)
        .run(supplierName, newName, newPhone, newEmail, now(), newSupplierId);
    }else{
      const supplierInfo = db.prepare(`INSERT INTO suppliers (name,contact,phone,email,address,lead_time,status,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(supplierName, newName, newPhone, newEmail, "", null, "active", now(), now());
      newSupplierId = supplierInfo.lastInsertRowid;
    }
  }

  db.prepare(`UPDATE users SET name=?, email=?, phone=?, role=?, status=?, password_hash=?, branch_id=?, username=?, staff_id=?, password_changed_at=?, supplier_id=? WHERE id=?`)
    .run(newName, newEmail, newPhone, newRole, newStatus, newHash, newBranch, newUsername || null, newStaffId || null, passwordChangedAt, newSupplierId, id);

  if(user.status === "pending" && newStatus === "active" && isVendorRole(newRole) && mailer && isEmail(newEmail)){
    const subject = "Vendor Account Approved";
    const text = `Hello ${newName}, your vendor account has been approved. You can now log in and post products.`;
    const html = `<p>Hello ${newName},</p><p>Your vendor account has been approved. You can now log in and post products.</p>`;
    sendEmail({ to: newEmail, subject, text, html }).catch(()=>{});
  }

  res.json({ success: true });
});

app.delete("/api/users/:id", authMiddleware, requireRole(["admin"]), (req, res) => {
  const id = Number(req.params.id);
  if(req.user.id === id) return sendError(res, 400, "Cannot delete current user");

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if(!user) return sendError(res, 404, "User not found");

  // PROTECTION: Prevent deleting locked admin accounts
  if(user.admin_locked){
    return sendError(res, 403, "Cannot delete a locked admin account. It is permanent and protected.");
  }

  if(user.role === "admin"){
    const admins = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get();
    if(admins.count <= 1) return sendError(res, 400, "At least one admin required");
  }

  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  res.json({ success: true });
});

// ===== User Lookup (for messaging) =====
app.get("/api/users/lookup", authMiddleware, (req, res) => {
  const current = req.user;
  const allowAll = current && ["admin","manager","supervisor"].includes(current.role);
  const params = [];
  let where = "WHERE status = 'active'";
  if(!allowAll && current && current.branch_id){
    where += " AND branch_id = ?";
    params.push(current.branch_id);
  }
  const rows = db.prepare(`SELECT id,name,role,branch_id FROM users ${where} ORDER BY name ASC`).all(...params);
  res.json(rows);
});

// ===== Messaging =====
app.get("/api/messages/threads", authMiddleware, (req, res) => {
  const userId = req.user.id;
  const threads = db.prepare(`
    SELECT t.id, t.name, t.type, t.branch_id, t.created_at,
      CASE
        WHEN t.type = 'direct' THEN (
          SELECT u.name FROM message_participants mp
          JOIN users u ON u.id = mp.user_id
          WHERE mp.thread_id = t.id AND u.id != ?
          LIMIT 1
        )
        WHEN t.type = 'broadcast' THEN 'Company Broadcast'
        ELSE t.name
      END as display_name,
      (SELECT sender_name FROM messages WHERE thread_id = t.id ORDER BY created_at DESC LIMIT 1) as last_sender,
      (SELECT content FROM messages WHERE thread_id = t.id ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE thread_id = t.id ORDER BY created_at DESC LIMIT 1) as last_at,
      (SELECT COUNT(*) FROM messages m WHERE m.thread_id = t.id AND m.id NOT IN (
        SELECT message_id FROM message_reads WHERE user_id = ?
      )) as unread_count
    FROM message_threads t
    LEFT JOIN message_participants p ON p.thread_id = t.id
    WHERE p.user_id = ? OR t.type = 'broadcast'
    GROUP BY t.id
    ORDER BY last_at DESC, t.id DESC
  `).all(userId, userId, userId);
  res.json(threads);
});

app.post("/api/messages/threads", authMiddleware, (req, res) => {
  const { type, name, participant_ids } = req.body || {};
  const userId = req.user.id;
  const userRole = req.user.role;
  if(!type) return sendError(res, 400, "Thread type required");

  if(type === "broadcast"){
    if(userRole !== "admin") return sendError(res, 403, "Only admin can broadcast");
    const thread = getBroadcastThread();
    return res.json({ id: thread.id });
  }

  if(type === "direct"){
    const targetId = participant_ids && participant_ids[0] ? Number(participant_ids[0]) : null;
    if(!targetId) return sendError(res, 400, "Recipient required");
    const existing = db.prepare(`
      SELECT t.id FROM message_threads t
      JOIN message_participants p1 ON p1.thread_id = t.id AND p1.user_id = ?
      JOIN message_participants p2 ON p2.thread_id = t.id AND p2.user_id = ?
      WHERE t.type = 'direct'
      LIMIT 1
    `).get(userId, targetId);
    if(existing) return res.json({ id: existing.id });
    const info = db.prepare(`INSERT INTO message_threads (name,type,created_by,branch_id,created_at)
      VALUES (?,?,?,?,?)`).run(null, "direct", userId, req.user.branch_id || null, now());
    const threadId = info.lastInsertRowid;
    const stmt = db.prepare(`INSERT INTO message_participants (thread_id,user_id,added_at) VALUES (?,?,?)`);
    stmt.run(threadId, userId, now());
    stmt.run(threadId, targetId, now());
    return res.json({ id: threadId });
  }

  if(type === "group"){
    if(!name) return sendError(res, 400, "Group name required");
    const ids = Array.isArray(participant_ids) ? participant_ids.map(Number).filter(Boolean) : [];
    if(ids.length === 0) return sendError(res, 400, "Participants required");
    const info = db.prepare(`INSERT INTO message_threads (name,type,created_by,branch_id,created_at)
      VALUES (?,?,?,?,?)`).run(name, "group", userId, req.user.branch_id || null, now());
    const threadId = info.lastInsertRowid;
    const stmt = db.prepare(`INSERT OR IGNORE INTO message_participants (thread_id,user_id,added_at) VALUES (?,?,?)`);
    stmt.run(threadId, userId, now());
    ids.forEach(pid => stmt.run(threadId, pid, now()));
    return res.json({ id: threadId });
  }

  return sendError(res, 400, "Invalid thread type");
});

app.get("/api/messages/threads/:id", authMiddleware, (req, res) => {
  const threadId = Number(req.params.id);
  const userId = req.user.id;
  const thread = db.prepare("SELECT * FROM message_threads WHERE id = ?").get(threadId);
  if(!thread) return sendError(res, 404, "Thread not found");
  if(thread.type !== "broadcast"){
    const member = db.prepare("SELECT id FROM message_participants WHERE thread_id = ? AND user_id = ?").get(threadId, userId);
    if(!member) return sendError(res, 403, "Forbidden");
  }
  const messages = db.prepare(`
    SELECT m.id,m.thread_id,m.sender_id,m.sender_name,m.content,m.attachments,m.created_at,
      (SELECT COUNT(*) FROM message_reads mr WHERE mr.message_id = m.id) as read_count
    FROM messages m
    WHERE m.thread_id = ?
    ORDER BY m.created_at ASC
  `).all(threadId);
  res.json({ thread, messages });
});

app.post("/api/messages/threads/:id", authMiddleware, (req, res) => {
  const threadId = Number(req.params.id);
  const { content, attachments } = req.body || {};
  const safeContent = content && String(content).trim().length ? String(content).trim() : "";
  const hasAttachments = Array.isArray(attachments) && attachments.length > 0;
  if(!safeContent && !hasAttachments) return sendError(res, 400, "Message content required");
  const thread = db.prepare("SELECT * FROM message_threads WHERE id = ?").get(threadId);
  if(!thread) return sendError(res, 404, "Thread not found");
  if(thread.type !== "broadcast"){
    const member = db.prepare("SELECT id FROM message_participants WHERE thread_id = ? AND user_id = ?").get(threadId, req.user.id);
    if(!member) return sendError(res, 403, "Forbidden");
  }else if(req.user.role !== "admin"){
    return sendError(res, 403, "Only admin can broadcast");
  }
  const info = db.prepare(`INSERT INTO messages (thread_id,sender_id,sender_name,content,attachments,created_at)
    VALUES (?,?,?,?,?,?)`)
    .run(threadId, req.user.id, req.user.name, safeContent, hasAttachments ? JSON.stringify(attachments) : null, now());
  db.prepare(`INSERT OR IGNORE INTO message_reads (message_id,user_id,read_at) VALUES (?,?,?)`)
    .run(info.lastInsertRowid, req.user.id, now());

  const preview = safeContent && safeContent.length ? safeContent.slice(0, 80) : "Attachment";
  const notificationPayload = {
    type: "Message",
    title: "New message",
    message: `${req.user.name}: ${preview}`,
    link: "messages.html"
  };

  if(thread.type === "broadcast"){
    const recipients = db.prepare("SELECT id FROM users WHERE status = 'active'").all();
    recipients.forEach(u => {
      if(u.id !== req.user.id) createNotification({ ...notificationPayload, user_id: u.id });
    });
  }else{
    const recipients = db.prepare(`SELECT user_id FROM message_participants WHERE thread_id = ?`).all(threadId);
    recipients.forEach(r => {
      if(r.user_id !== req.user.id){
        createNotification({ ...notificationPayload, user_id: r.user_id });
      }
    });
  }

  res.json({ id: info.lastInsertRowid });
});

app.post("/api/messages/threads/:id/read", authMiddleware, (req, res) => {
  const threadId = Number(req.params.id);
  const userId = req.user.id;
  const thread = db.prepare("SELECT * FROM message_threads WHERE id = ?").get(threadId);
  if(!thread) return sendError(res, 404, "Thread not found");
  if(thread.type !== "broadcast"){
    const member = db.prepare("SELECT id FROM message_participants WHERE thread_id = ? AND user_id = ?").get(threadId, userId);
    if(!member) return sendError(res, 403, "Forbidden");
  }
  const messages = db.prepare("SELECT id FROM messages WHERE thread_id = ?").all(threadId);
  const stmt = db.prepare(`INSERT OR IGNORE INTO message_reads (message_id,user_id,read_at) VALUES (?,?,?)`);
  messages.forEach(m => stmt.run(m.id, userId, now()));
  res.json({ success: true });
});

// ===== Notifications =====
app.get("/api/notifications", authMiddleware, (req, res) => {
  const status = req.query.status;
  const params = [req.user.id];
  let where = "WHERE user_id = ?";
  if(status){
    where += " AND status = ?";
    params.push(status);
  }
  const rows = db.prepare(`SELECT * FROM notifications ${where} ORDER BY created_at DESC LIMIT 100`).all(...params);
  res.json(rows);
});

app.post("/api/notifications", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { user_id, role, branch_id, type, title, message, link } = req.body || {};
  if(!type || !message) return sendError(res, 400, "Type and message required");
  if(user_id){
    createNotification({ user_id: Number(user_id), type, title, message, link });
    return res.json({ success: true });
  }
  if(role){
    notifyUsersByRoles([role], { type, title, message, link }, branch_id ? Number(branch_id) : null);
    return res.json({ success: true });
  }
  return sendError(res, 400, "Specify user_id or role");
});

app.post("/api/notifications/mark-read", authMiddleware, (req, res) => {
  const { id, all } = req.body || {};
  if(all){
    db.prepare("UPDATE notifications SET status = 'read' WHERE user_id = ?").run(req.user.id);
    return res.json({ success: true });
  }
  if(!id) return sendError(res, 400, "Notification id required");
  db.prepare("UPDATE notifications SET status = 'read' WHERE id = ? AND user_id = ?").run(Number(id), req.user.id);
  res.json({ success: true });
});

// ===== Branches =====
app.get("/api/branches", authMiddleware, (req, res) => {
  const rows = db.prepare("SELECT * FROM branches ORDER BY id ASC").all();
  res.json(rows);
});

app.post("/api/branches", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { name, location, manager_name, phone, email, status } = req.body || {};
  if(!name) return sendError(res, 400, "Branch name required");
  const exists = db.prepare("SELECT id FROM branches WHERE name = ?").get(name);
  if(exists) return sendError(res, 400, "Branch already exists");

  const stmt = db.prepare(`INSERT INTO branches (name,location,manager_name,phone,email,status,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?)`);
  const info = stmt.run(name, location || "", manager_name || "", phone || "", email || "", status || "active", now(), now());
  res.json({ id: info.lastInsertRowid });
});

app.put("/api/branches/:id", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM branches WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Branch not found");

  const { name, location, manager_name, phone, email, status } = req.body || {};
  const newName = name || existing.name;
  const newLocation = location ?? existing.location;
  const newManager = manager_name ?? existing.manager_name;
  const newPhone = phone ?? existing.phone;
  const newEmail = email ?? existing.email;
  const newStatus = status || existing.status;

  db.prepare(`UPDATE branches SET name=?, location=?, manager_name=?, phone=?, email=?, status=?, updated_at=? WHERE id=?`)
    .run(newName, newLocation, newManager, newPhone, newEmail, newStatus, now(), id);
  res.json({ success: true });
});

app.delete("/api/branches/:id", authMiddleware, requireRole(["admin"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM branches WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Branch not found");

  const usage = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM users WHERE branch_id = ?) as users,
      (SELECT COUNT(*) FROM products WHERE branch_id = ?) as products,
      (SELECT COUNT(*) FROM sales WHERE branch_id = ?) as sales,
      (SELECT COUNT(*) FROM purchase_orders WHERE branch_id = ?) as orders,
      (SELECT COUNT(*) FROM inventory_movements WHERE branch_id = ?) as moves
  `).get(id,id,id,id,id);

  const total = (usage.users || 0) + (usage.products || 0) + (usage.sales || 0) + (usage.orders || 0) + (usage.moves || 0);
  if(total > 0) return sendError(res, 400, "Branch has linked records and cannot be deleted");

  db.prepare("DELETE FROM branches WHERE id = ?").run(id);
  res.json({ success: true });
});

// ===== Warehouses =====
app.get("/api/warehouses", authMiddleware, (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  const where = branchId ? "WHERE w.branch_id = ?" : "";
  if(branchId) params.push(branchId);
  const rows = db.prepare(`
    SELECT w.*, b.name as branch_name
    FROM warehouses w
    LEFT JOIN branches b ON w.branch_id = b.id
    ${where}
    ORDER BY w.id DESC
  `).all(...params);
  res.json(rows);
});

app.post("/api/warehouses", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { name, location, capacity, status, branch_id } = req.body || {};
  if(!name) return sendError(res, 400, "Warehouse name required");
  const branchId = branch_id ? Number(branch_id) : resolveBranchIdFromBody(req);
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");

  const info = db.prepare(`INSERT INTO warehouses (name,location,capacity,status,branch_id,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?)`)
    .run(name, location || "", Number(capacity) || null, status || "active", branchId, now(), now());
  logActivity(req.user, "warehouse_create", "warehouses", info.lastInsertRowid, name, branchId);
  res.json({ id: info.lastInsertRowid });
});

app.put("/api/warehouses/:id", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM warehouses WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Warehouse not found");
  const { name, location, capacity, status, branch_id } = req.body || {};
  const branchId = branch_id ? Number(branch_id) : existing.branch_id;
  if(branchId && !getBranchById(branchId)) return sendError(res, 400, "Branch not found");

  db.prepare(`UPDATE warehouses SET name=?, location=?, capacity=?, status=?, branch_id=?, updated_at=? WHERE id=?`)
    .run(name || existing.name, location ?? existing.location, capacity ?? existing.capacity, status || existing.status, branchId, now(), id);
  logActivity(req.user, "warehouse_update", "warehouses", id, name || existing.name, branchId);
  res.json({ success: true });
});

app.delete("/api/warehouses/:id", authMiddleware, requireRole(["admin"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM warehouses WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Warehouse not found");
  const used = db.prepare("SELECT COUNT(*) as count FROM products WHERE warehouse_id = ?").get(id).count;
  if(used > 0) return sendError(res, 400, "Warehouse has linked products");
  db.prepare("DELETE FROM warehouses WHERE id = ?").run(id);
  logActivity(req.user, "warehouse_delete", "warehouses", id, existing.name, existing.branch_id);
  res.json({ success: true });
});

// ===== Attendance =====
app.post("/api/biometric/register/options", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT id,name,email FROM users WHERE id = ?").get(req.user.id);
  if(!user) return sendError(res, 404, "User not found");

  const credentials = db.prepare("SELECT * FROM webauthn_credentials WHERE user_id = ?").all(user.id);
  const options = generateRegistrationOptions({
    rpName: "SmartInventory Pro",
    rpID: getExpectedRpId(req),
    userID: String(user.id),
    userName: user.email || user.name || `user-${user.id}`,
    userDisplayName: user.name || user.email || `User ${user.id}`,
    attestationType: "none",
    authenticatorSelection: { userVerification: "preferred" },
    excludeCredentials: credentials.map(cred => ({
      id: isoBase64URL.toBuffer(cred.credential_id),
      type: "public-key",
      transports: cred.transports ? JSON.parse(cred.transports) : undefined
    }))
  });

  saveWebAuthnChallenge(user.id, "register", options.challenge);
  res.json(options);
});

app.post("/api/biometric/register/verify", authMiddleware, async (req, res) => {
  const user = db.prepare("SELECT id,name,email FROM users WHERE id = ?").get(req.user.id);
  if(!user) return sendError(res, 404, "User not found");
  const { response } = req.body || {};
  if(!response) return sendError(res, 400, "Response required");

  const challenge = getWebAuthnChallenge(user.id, "register");
  if(!challenge) return sendError(res, 400, "Registration challenge expired");

  try{
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: getExpectedOrigin(req),
      expectedRPID: getExpectedRpId(req)
    });
    if(!verification.verified || !verification.registrationInfo){
      return sendError(res, 400, "Biometric registration failed");
    }
    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
    const credentialId = isoBase64URL.fromBuffer(credentialID);
    const publicKey = isoBase64URL.fromBuffer(credentialPublicKey);

    const existing = db.prepare("SELECT id FROM webauthn_credentials WHERE credential_id = ?").get(credentialId);
    if(existing){
      return res.json({ success: true, alreadyRegistered: true });
    }

    db.prepare(`INSERT INTO webauthn_credentials (user_id,credential_id,public_key,counter,transports,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?)`).run(
      user.id,
      credentialId,
      publicKey,
      counter || 0,
      JSON.stringify(response.transports || []),
      now(),
      now()
    );
    db.prepare("DELETE FROM webauthn_challenges WHERE id = ?").run(challenge.id);
    res.json({ success: true });
  }catch(err){
    return sendError(res, 400, err && err.message ? err.message : "Biometric registration failed");
  }
});

app.post("/api/biometric/auth/options", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT id FROM users WHERE id = ?").get(req.user.id);
  if(!user) return sendError(res, 404, "User not found");
  const credentials = db.prepare("SELECT * FROM webauthn_credentials WHERE user_id = ?").all(user.id);
  if(credentials.length === 0) return sendError(res, 400, "No biometric credentials enrolled");

  const options = generateAuthenticationOptions({
    rpID: getExpectedRpId(req),
    userVerification: "preferred",
    allowCredentials: credentials.map(cred => ({
      id: isoBase64URL.toBuffer(cred.credential_id),
      type: "public-key",
      transports: cred.transports ? JSON.parse(cred.transports) : undefined
    }))
  });
  saveWebAuthnChallenge(user.id, "auth", options.challenge);
  res.json(options);
});

app.post("/api/biometric/attendance", authMiddleware, async (req, res) => {
  const { response, branch_id, location } = req.body || {};
  if(!response) return sendError(res, 400, "Response required");

  const user = db.prepare("SELECT id,name,branch_id FROM users WHERE id = ?").get(req.user.id);
  if(!user) return sendError(res, 404, "User not found");
  const challenge = getWebAuthnChallenge(user.id, "auth");
  if(!challenge) return sendError(res, 400, "Authentication challenge expired");

  const credential = db.prepare("SELECT * FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?").get(user.id, response.id);
  if(!credential) return sendError(res, 400, "Credential not found");

  try{
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: getExpectedOrigin(req),
      expectedRPID: getExpectedRpId(req),
      authenticator: {
        credentialID: isoBase64URL.toBuffer(credential.credential_id),
        credentialPublicKey: isoBase64URL.toBuffer(credential.public_key),
        counter: credential.counter
      }
    });
    if(!verification.verified){
      return sendError(res, 400, "Biometric verification failed");
    }

    const newCounter = verification.authenticationInfo ? verification.authenticationInfo.newCounter : credential.counter;
    db.prepare("UPDATE webauthn_credentials SET counter = ?, updated_at = ? WHERE id = ?").run(newCounter, now(), credential.id);
    db.prepare("DELETE FROM webauthn_challenges WHERE id = ?").run(challenge.id);

    const branchId = branch_id ? Number(branch_id) : (user.branch_id || resolveBranchIdFromBody(req));
    if(!branchId) return sendError(res, 400, "Branch required");

    const open = db.prepare("SELECT * FROM attendance WHERE user_id = ? AND date = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1")
      .get(user.id, today());
    if(!open){
      const info = db.prepare(`INSERT INTO attendance (user_id,branch_id,date,clock_in,method,created_at,device,location)
        VALUES (?,?,?,?,?,?,?,?)`)
        .run(user.id, branchId, today(), now(), "biometric", now(), req.headers["user-agent"] || null, location || null);
      logActivity(req.user, "clock_in", "attendance", info.lastInsertRowid, "Biometric clock-in", branchId);
      return res.json({ success: true, action: "clock_in" });
    }

    const clockOut = now();
    const hours = (new Date(clockOut) - new Date(open.clock_in)) / 3600000;
    const clockInDate = new Date(open.clock_in);
    const late = clockInDate.getHours() > 9 || (clockInDate.getHours() === 9 && clockInDate.getMinutes() > 10);
    let status = late ? "late" : "on_time";
    if(hours > 8) status = status === "late" ? "late_overtime" : "overtime";
    db.prepare("UPDATE attendance SET clock_out = ?, total_hours = ?, status = ? WHERE id = ?")
      .run(clockOut, Math.max(0, Number(hours.toFixed(2))), status, open.id);
    logActivity(req.user, "clock_out", "attendance", open.id, "Biometric clock-out", open.branch_id);
    res.json({ success: true, action: "clock_out", total_hours: Number(hours.toFixed(2)), status });
  }catch(err){
    return sendError(res, 400, err && err.message ? err.message : "Biometric verification failed");
  }
});

// ===== Face Recognition Attendance =====
app.post("/api/face/enroll", authMiddleware, (req, res) => {
  const descriptor = parseFaceDescriptor(req.body && req.body.descriptor);
  if(!descriptor) return sendError(res, 400, "Invalid face descriptor");

  db.prepare("DELETE FROM face_embeddings WHERE user_id = ?").run(req.user.id);
  db.prepare(`INSERT INTO face_embeddings (user_id,descriptor,created_at,updated_at)
    VALUES (?,?,?,?)`).run(req.user.id, JSON.stringify(descriptor), now(), now());
  res.json({ success: true });
});

app.post("/api/face/attendance", authMiddleware, (req, res) => {
  const descriptor = parseFaceDescriptor(req.body && req.body.descriptor);
  if(!descriptor) return sendError(res, 400, "Invalid face descriptor");
  const location = req.body && req.body.location || null;
  const requestedBranch = req.body && req.body.branch_id ? Number(req.body.branch_id) : null;
  const privileged = ["admin","manager","supervisor"].includes(req.user.role);
  const scope = privileged && req.body && req.body.scope === "all" ? "all" : "self";

  let candidates = [];
  if(scope === "self"){
    const rows = db.prepare("SELECT e.descriptor, u.id, u.name, u.role, u.branch_id FROM face_embeddings e JOIN users u ON e.user_id = u.id WHERE u.id = ?").all(req.user.id);
    candidates = rows.map(r => ({ ...r, descriptor: parseFaceDescriptor(JSON.parse(r.descriptor)) }));
  }else{
    const params = [];
    let where = "WHERE u.status = 'active'";
    if(requestedBranch){
      where += " AND u.branch_id = ?";
      params.push(requestedBranch);
    }
    const rows = db.prepare(`SELECT e.descriptor, u.id, u.name, u.role, u.branch_id FROM face_embeddings e JOIN users u ON e.user_id = u.id ${where}`).all(...params);
    candidates = rows.map(r => ({ ...r, descriptor: parseFaceDescriptor(JSON.parse(r.descriptor)) }));
  }

  candidates = candidates.filter(c => Array.isArray(c.descriptor));
  if(candidates.length === 0) return sendError(res, 400, "No enrolled faces found");

  let best = null;
  candidates.forEach(candidate => {
    const distance = euclideanDistance(descriptor, candidate.descriptor);
    if(!best || distance < best.distance){
      best = { ...candidate, distance };
    }
  });

  if(!best || best.distance > FACE_MATCH_THRESHOLD){
    return sendError(res, 400, "Face not recognized");
  }

  const branchId = requestedBranch || best.branch_id || req.user.branch_id;
  if(!branchId) return sendError(res, 400, "Branch required");

  const open = db.prepare("SELECT * FROM attendance WHERE user_id = ? AND date = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1")
    .get(best.id, today());
  if(!open){
    const info = db.prepare(`INSERT INTO attendance (user_id,branch_id,date,clock_in,method,created_at,device,location)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(best.id, branchId, today(), now(), "face", now(), req.headers["user-agent"] || null, location || null);
    logActivity(req.user, "clock_in", "attendance", info.lastInsertRowid, `Face clock-in for ${best.name}`, branchId);
    return res.json({ success: true, action: "clock_in", user: { id: best.id, name: best.name, role: best.role } });
  }

  const clockOut = now();
  const hours = (new Date(clockOut) - new Date(open.clock_in)) / 3600000;
  const clockInDate = new Date(open.clock_in);
  const late = clockInDate.getHours() > 9 || (clockInDate.getHours() === 9 && clockInDate.getMinutes() > 10);
  let status = late ? "late" : "on_time";
  if(hours > 8) status = status === "late" ? "late_overtime" : "overtime";
  db.prepare("UPDATE attendance SET clock_out = ?, total_hours = ?, status = ? WHERE id = ?")
    .run(clockOut, Math.max(0, Number(hours.toFixed(2))), status, open.id);
  logActivity(req.user, "clock_out", "attendance", open.id, `Face clock-out for ${best.name}`, branchId);
  res.json({ success: true, action: "clock_out", total_hours: Number(hours.toFixed(2)), status, user: { id: best.id, name: best.name, role: best.role } });
});

// ===== Vendor Analytics & Orders =====
app.get("/api/vendor/analytics", authMiddleware, requireRole(["supplier","seller","retailer","wholesaler"]), (req, res) => {
  const totalProducts = db.prepare("SELECT COUNT(*) as count FROM products WHERE owner_user_id = ?").get(req.user.id).count;
  const publishedProducts = db.prepare("SELECT COUNT(*) as count FROM products WHERE owner_user_id = ? AND is_published = 1").get(req.user.id).count;
  const totalStock = db.prepare("SELECT COALESCE(SUM(quantity),0) as total FROM products WHERE owner_user_id = ?").get(req.user.id).total;

  const productIds = db.prepare("SELECT id FROM products WHERE owner_user_id = ?").all(req.user.id).map(r => r.id);
  let orderCount = 0;
  let revenue = 0;
  if(productIds.length){
    const orders = db.prepare("SELECT id, items_json FROM shopfront_orders ORDER BY created_at DESC").all();
    orders.forEach(order => {
      const items = safeParseJson(order.items_json, []);
      let has = false;
      items.forEach(item => {
        if(productIds.includes(item.product_id)){
          has = true;
          revenue += (Number(item.price) || 0) * (Number(item.qty) || 0);
        }
      });
      if(has) orderCount++;
    });
  }

  res.json({
    total_products: totalProducts,
    published_products: publishedProducts,
    total_stock: Number(totalStock) || 0,
    online_orders: orderCount,
    online_revenue: Number(revenue.toFixed(2))
  });
});

app.get("/api/vendor/purchase-orders", authMiddleware, requireRole(["supplier","seller","retailer","wholesaler"]), (req, res) => {
  let supplierId = req.user.supplier_id;
  if(!supplierId){
    const byEmail = db.prepare("SELECT id FROM suppliers WHERE email = ?").get(req.user.email);
    if(byEmail) supplierId = byEmail.id;
  }
  if(!supplierId){
    return res.json([]);
  }
  const rows = db.prepare(`SELECT po.*, b.name as branch_name FROM purchase_orders po
    LEFT JOIN branches b ON po.branch_id = b.id
    WHERE po.supplier_id = ?
    ORDER BY po.created_at DESC`).all(supplierId);
  res.json(rows);
});

app.post("/api/vendor/purchase-orders/:id/status", authMiddleware, requireRole(["supplier","seller","retailer","wholesaler"]), (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body || {};
  if(!status) return sendError(res, 400, "Status required");
  const order = db.prepare("SELECT * FROM purchase_orders WHERE id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");
  if(req.user.supplier_id && Number(order.supplier_id) !== Number(req.user.supplier_id)){
    return sendError(res, 403, "Not your purchase order");
  }
  db.prepare("UPDATE purchase_orders SET status = ? WHERE id = ?").run(status, id);
  res.json({ success: true });
});

app.post("/api/attendance/clock-in", authMiddleware, (req, res) => {
  const branchId = resolveBranchIdFromBody(req) || req.user.branch_id;
  if(!branchId) return sendError(res, 400, "Branch required");
  const open = db.prepare("SELECT id FROM attendance WHERE user_id = ? AND date = ? AND clock_out IS NULL").get(req.user.id, today());
  if(open) return sendError(res, 400, "Already clocked in");

  const info = db.prepare(`INSERT INTO attendance (user_id,branch_id,date,clock_in,method,created_at,device,location)
    VALUES (?,?,?,?,?,?,?,?)`)
    .run(req.user.id, branchId, today(), now(), "manual", now(), req.headers["user-agent"] || null, req.body && req.body.location || null);
  logActivity(req.user, "clock_in", "attendance", info.lastInsertRowid, "Manual clock-in", branchId);
  res.json({ success: true });
});

app.post("/api/attendance/clock-out", authMiddleware, (req, res) => {
  const open = db.prepare("SELECT * FROM attendance WHERE user_id = ? AND date = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1")
    .get(req.user.id, today());
  if(!open) return sendError(res, 400, "No open clock-in found");
  const clockOut = now();
  const hours = (new Date(clockOut) - new Date(open.clock_in)) / 3600000;
  const clockInDate = new Date(open.clock_in);
  const late = clockInDate.getHours() > 9 || (clockInDate.getHours() === 9 && clockInDate.getMinutes() > 10);
  let status = late ? "late" : "on_time";
  if(hours > 8) status = status === "late" ? "late_overtime" : "overtime";

  db.prepare("UPDATE attendance SET clock_out = ?, total_hours = ?, status = ? WHERE id = ?")
    .run(clockOut, Math.max(0, Number(hours.toFixed(2))), status, open.id);
  logActivity(req.user, "clock_out", "attendance", open.id, "Manual clock-out", open.branch_id);
  res.json({ success: true, total_hours: Number(hours.toFixed(2)), status });
});

app.get("/api/attendance/today", authMiddleware, (req, res) => {
  const record = db.prepare("SELECT * FROM attendance WHERE user_id = ? AND date = ? ORDER BY clock_in DESC LIMIT 1")
    .get(req.user.id, today());
  res.json(record || null);
});

app.get("/api/attendance", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const { date, from, to } = req.query;
  const clauses = [];
  const params = [];
  if(branchId){
    clauses.push("a.branch_id = ?");
    params.push(branchId);
  }
  if(date){
    clauses.push("a.date = ?");
    params.push(date);
  }else{
    const range = buildDateWhere("a.clock_in", from, to);
    clauses.push(...range.clauses);
    params.push(...range.params);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = db.prepare(`
    SELECT a.*, u.name as user_name, u.role, b.name as branch_name
    FROM attendance a
    JOIN users u ON a.user_id = u.id
    LEFT JOIN branches b ON a.branch_id = b.id
    ${where}
    ORDER BY a.clock_in DESC
  `).all(...params);
  res.json(rows);
});

app.get("/api/attendance/summary", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const date = req.query.date || today();
  const params = [];
  let branchWhere = "";
  if(branchId){
    branchWhere = "AND branch_id = ?";
    params.push(branchId);
  }
  const totalStaff = db.prepare(`SELECT COUNT(*) as count FROM users WHERE status = 'active' ${branchWhere}`).get(...params).count;
  const present = db.prepare(`SELECT COUNT(DISTINCT user_id) as count FROM attendance WHERE date = ? ${branchWhere}`).get(date, ...params).count;
  const late = db.prepare(`SELECT COUNT(*) as count FROM attendance WHERE date = ? AND status LIKE 'late%' ${branchWhere}`).get(date, ...params).count;
  res.json({ date, total_staff: totalStaff, present, absent: Math.max(0, totalStaff - present), late });
});

// ===== Feedback =====
app.post("/api/feedback", authMiddleware, (req, res) => {
  const { message, rating } = req.body || {};
  if(!message) return sendError(res, 400, "Message required");
  const rate = rating !== undefined && rating !== null ? Number(rating) : null;
  const info = db.prepare(`INSERT INTO feedback (user_id,user_name,branch_id,rating,message,created_at)
    VALUES (?,?,?,?,?,?)`)
    .run(req.user.id, req.user.name, req.user.branch_id || null, Number.isFinite(rate) ? rate : null, message, now());
  logActivity(req.user, "feedback", "feedback", info.lastInsertRowid, "Feedback submitted", req.user.branch_id);
  res.json({ success: true });
});

app.get("/api/feedback", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  const where = branchId ? "WHERE branch_id = ?" : "";
  if(branchId) params.push(branchId);
  const rows = db.prepare(`SELECT * FROM feedback ${where} ORDER BY created_at DESC`).all(...params);
  res.json(rows);
});

// ===== Referrals =====
app.get("/api/referral", authMiddleware, (req, res) => {
  let referral = db.prepare("SELECT * FROM referrals WHERE user_id = ?").get(req.user.id);
  if(!referral){
    const code = `REF${req.user.id}${Math.floor(1000 + Math.random() * 9000)}`;
    const info = db.prepare(`INSERT INTO referrals (user_id,code,created_at) VALUES (?,?,?)`)
      .run(req.user.id, code, now());
    referral = { id: info.lastInsertRowid, user_id: req.user.id, code, created_at: now() };
  }
  res.json(referral);
});

app.post("/api/referral/invite", authMiddleware, (req, res) => {
  const { name, contact } = req.body || {};
  const referral = db.prepare("SELECT * FROM referrals WHERE user_id = ?").get(req.user.id);
  if(!referral) return sendError(res, 400, "Referral code missing");
  const info = db.prepare(`INSERT INTO referral_invites (referral_id,name,contact,created_at)
    VALUES (?,?,?,?)`)
    .run(referral.id, name || "", contact || "", now());
  res.json({ id: info.lastInsertRowid });
});

app.get("/api/referral/invites", authMiddleware, (req, res) => {
  const referral = db.prepare("SELECT * FROM referrals WHERE user_id = ?").get(req.user.id);
  if(!referral) return res.json([]);
  const rows = db.prepare("SELECT * FROM referral_invites WHERE referral_id = ? ORDER BY created_at DESC").all(referral.id);
  res.json(rows);
});

// ===== Requests (Franchise / Printer) =====
app.post("/api/requests", authMiddleware, (req, res) => {
  const { type, requester_name, contact, details, branch_id } = req.body || {};
  if(!type) return sendError(res, 400, "Request type required");
  const branchId = branch_id ? Number(branch_id) : (req.user.branch_id || null);
  const info = db.prepare(`INSERT INTO requests (type,requester_name,contact,branch_id,details,created_at)
    VALUES (?,?,?,?,?,?)`)
    .run(type, requester_name || req.user.name, contact || req.user.email || "", branchId, details || "", now());
  logActivity(req.user, "request", "requests", info.lastInsertRowid, type, branchId);
  res.json({ id: info.lastInsertRowid });
});

app.get("/api/requests", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  const where = branchId ? "WHERE r.branch_id = ?" : "";
  if(branchId) params.push(branchId);
  const rows = db.prepare(`SELECT r.*, b.name as branch_name FROM requests r LEFT JOIN branches b ON r.branch_id = b.id ${where} ORDER BY r.created_at DESC`).all(...params);
  res.json(rows);
});

// ===== Shopfront Orders =====
app.post("/api/shopfront/orders", authMiddleware, (req, res) => {
  const { customer_name, contact, items, branch_id, delivery_type, delivery_address, delivery_phone, payment_method, payment_reference, mpesa_account_id } = req.body || {};
  const branchId = branch_id ? Number(branch_id) : resolveBranchIdFromBody(req);
  const result = createShopfrontOrder({
    customer_name,
    contact,
    items,
    branch_id: branchId,
    delivery_type,
    delivery_address,
    delivery_phone,
    payment_method,
    payment_reference,
    mpesa_account_id
  });
  if(result.error) return sendError(res, 400, result.error);

  notifyUsersByRoles(
    ["admin","manager","supervisor"],
    { type: "Sales", title: "New Online Order", message: `Order #${result.id} placed for KES ${Number(result.total).toFixed(2)}`, link: "shopfront.html" },
    branchId
  );

  if(result.status === "Ready for Delivery"){
    notifyUsersByRoles(
      ["rider"],
      { type: "Delivery", title: "Order Ready", message: `Order #${result.id} is ready for delivery.`, link: "delivery.html" },
      branchId
    );
  }

  const createdOrder = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(result.id);
  if(createdOrder){
    const template = {
      subject: "Order Confirmation - #{{orderId}}",
      text: "Thank you for your order #{{orderId}}. Status: {{status}}. Track here: {{trackUrl}}. OTP: {{otp}}",
      html: "<p>Thank you for your order <strong>#{{orderId}}</strong>.</p><p>Status: <strong>{{status}}</strong></p><p>Track here: <a href=\"{{trackUrl}}\">{{trackUrl}}</a></p><p>OTP: <strong>{{otp}}</strong></p>"
    };
    notifyOrderByEmail(normalizeShopfrontOrder(createdOrder), template);
  }

  res.json(result);
});

app.get("/api/shopfront/orders", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  const where = branchId ? "WHERE o.branch_id = ?" : "";
  if(branchId) params.push(branchId);
  const rows = db.prepare(`SELECT o.*, b.name as branch_name FROM shopfront_orders o LEFT JOIN branches b ON o.branch_id = b.id ${where} ORDER BY o.created_at DESC`).all(...params);
  res.json(rows.map(r => normalizeShopfrontOrder(r)));
});

// ===== Public Shopfront (No Auth) =====
app.get("/api/public/branches", (req, res) => {
  const rows = db.prepare("SELECT id,name,location,status FROM branches WHERE status = 'active' ORDER BY id ASC").all();
  res.json(rows);
});

app.get("/api/public/settings", (req, res) => {
  const branchRaw = req.query.branch_id;
  const branchId = branchRaw ? Number(branchRaw) : 0;
  const settings = getSettingsForBranch(branchId);
  const mpesaAccount = getDefaultMpesaAccountForBranch(branchId);
  res.json({
    delivery_fee: Number(settings.delivery_fee || 0),
    shopfront_enabled: settings.shopfront_enabled !== false,
    site_footer_text: settings.site_footer_text || DEFAULT_SETTINGS.site_footer_text,
    payment_modes: Array.isArray(settings.payment_modes) ? settings.payment_modes : DEFAULT_SETTINGS.payment_modes,
    mpesa_account: mpesaAccount ? {
      id: mpesaAccount.id,
      account_name: mpesaAccount.account_name,
      business_type: mpesaAccount.business_type,
      shortcode: mpesaAccount.shortcode,
      phone_number: mpesaAccount.phone_number || "",
      account_reference: mpesaAccount.account_reference || "Order Payment",
      transaction_description: mpesaAccount.transaction_description || "Customer order payment",
      enable_stk_push: !!mpesaAccount.enable_stk_push,
      enable_c2b: !!mpesaAccount.enable_c2b,
      environment: mpesaAccount.environment,
      status: mpesaAccount.status
    } : null
  });
});

app.get("/api/public/products", (req, res) => {
  let branchId = Number(req.query.branch_id);
  if(!branchId){
    const branch = db.prepare("SELECT id FROM branches ORDER BY id ASC LIMIT 1").get();
    branchId = branch ? branch.id : null;
  }
  if(!branchId) return sendError(res, 400, "Branch required");
  const rows = db.prepare(`
    SELECT p.id, p.name, p.category, p.quantity,
           COALESCE(pp.price, p.price) as price
    FROM products p
    LEFT JOIN product_prices pp ON pp.product_id = p.id AND pp.branch_id = ?
    WHERE (p.branch_id = ? OR p.branch_id IS NULL) AND p.quantity > 0 AND COALESCE(p.is_published, 1) = 1
    ORDER BY p.name ASC
  `).all(branchId, branchId);
  res.json(rows);
});

app.post("/api/public/orders", (req, res) => {
  const { customer_name, contact, items, branch_id, delivery_type, delivery_address, delivery_phone, payment_method, payment_reference, mpesa_account_id } = req.body || {};
  const result = createShopfrontOrder({
    customer_name,
    contact,
    items,
    branch_id,
    delivery_type,
    delivery_address,
    delivery_phone,
    payment_method,
    payment_reference,
    mpesa_account_id
  });
  if(result.error) return sendError(res, 400, result.error);

  notifyUsersByRoles(
    ["admin","manager","supervisor"],
    { type: "Sales", title: "New Online Order", message: `Order #${result.id} placed for KES ${Number(result.total).toFixed(2)}`, link: "shopfront.html" },
    Number(branch_id) || null
  );

  if(result.status === "Ready for Delivery"){
    notifyUsersByRoles(
      ["rider"],
      { type: "Delivery", title: "Order Ready", message: `Order #${result.id} is ready for delivery.`, link: "delivery.html" },
      Number(branch_id) || null
    );
  }

  const createdOrder = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(result.id);
  if(createdOrder){
    const template = {
      subject: "Order Confirmation - #{{orderId}}",
      text: "Thank you for your order #{{orderId}}. Status: {{status}}. Track here: {{trackUrl}}. OTP: {{otp}}",
      html: "<p>Thank you for your order <strong>#{{orderId}}</strong>.</p><p>Status: <strong>{{status}}</strong></p><p>Track here: <a href=\"{{trackUrl}}\">{{trackUrl}}</a></p><p>OTP: <strong>{{otp}}</strong></p>"
    };
    notifyOrderByEmail(normalizeShopfrontOrder(createdOrder), template);
  }

  res.json(result);
});

app.get("/api/shopfront/orders/:id", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const id = Number(req.params.id);
  const order = db.prepare("SELECT o.*, b.name as branch_name FROM shopfront_orders o LEFT JOIN branches b ON o.branch_id = b.id WHERE o.id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");
  res.json(normalizeShopfrontOrder(order));
});

app.post("/api/shopfront/orders/:id/status", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body || {};
  if(!status) return sendError(res, 400, "Status required");
  const order = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");

  const extra = {};
  if(status === "Delivered" || status === "Picked Up"){
    extra.delivered_at = now();
  }
  if(status === "Payment Confirmed"){
    extra.payment_status = "Paid";
    extra.paid_amount = order.total;
    extra.paid_at = now();
  }

  const cancelStatuses = ["Cancelled", "Rejected"];
  let updated = null;
  if(cancelStatuses.includes(status) && Number(order.stock_committed || 0) === 1){
    const items = safeParseJson(order.items_json, []);
    const updateProduct = db.prepare("UPDATE products SET quantity = quantity + ?, updated_at = ? WHERE id = ?");
    const insertMove = db.prepare(`INSERT INTO inventory_movements (product_id,product_name,type,qty,reference,note,user_id,user_name,branch_id,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)`);
    const trx = db.transaction(() => {
      items.forEach(item => {
        if(!item || !item.product_id || !item.qty) return;
        updateProduct.run(Number(item.qty), now(), item.product_id);
        insertMove.run(
          item.product_id,
          item.name || "Product",
          "RETURN",
          Number(item.qty),
          `ORDER#${order.id}`,
          `Order ${status}`,
          req.user.id,
          req.user.name,
          order.branch_id || null,
          now()
        );
      });
      return updateOrderStatus(id, status, { ...extra, cancelled_at: now(), stock_committed: 0 });
    });
    updated = trx();
  }else{
    updated = updateOrderStatus(id, status, extra);
  }
  if(!updated) return sendError(res, 500, "Update failed");

  if(status === "Ready for Delivery"){
    notifyUsersByRoles(
      ["rider"],
      { type: "Delivery", title: "Order Ready", message: `Order #${order.id} is ready for delivery.`, link: "delivery.html" },
      order.branch_id || null
    );
  }

  const normalized = normalizeShopfrontOrder(updated);
  const template = {
    subject: "Order Update - #{{orderId}}",
    text: "Order #{{orderId}} status changed to {{status}}. Track here: {{trackUrl}}.",
    html: "<p>Your order <strong>#{{orderId}}</strong> status is now <strong>{{status}}</strong>.</p><p>Track here: <a href=\"{{trackUrl}}\">{{trackUrl}}</a></p>"
  };
  notifyOrderByEmail(normalized, template);
  res.json(normalized);
});

app.post("/api/shopfront/orders/:id/payment", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const id = Number(req.params.id);
  const { payment_status, payment_method, payment_reference, paid_amount } = req.body || {};
  const order = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");

  const status = payment_status || "Paid";
  const method = payment_method || order.payment_method || null;
  const reference = payment_reference || order.payment_reference || null;
  const amount = status === "Paid" ? (Number.isFinite(Number(paid_amount)) ? Number(paid_amount) : Number(order.total || 0)) : null;
  const paidAt = status === "Paid" ? now() : null;

  const trx = db.transaction(() => {
    const payload = {
      payment_status: status,
      payment_method: method,
      payment_reference: reference,
      paid_amount: amount,
      paid_at: paidAt,
      updated_at: now()
    };
    const fields = Object.keys(payload);
    const setClause = fields.map(key => `${key} = ?`).join(", ");
    const values = fields.map(key => payload[key]);
    values.push(id);
    db.prepare(`UPDATE shopfront_orders SET ${setClause} WHERE id = ?`).run(...values);

    if(status === "Paid"){
      const refreshed = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
      const timeline = ensureTimeline(refreshed, "Payment Confirmed");
      db.prepare("UPDATE shopfront_orders SET tracking_timeline = ?, updated_at = ? WHERE id = ?")
        .run(JSON.stringify(timeline), now(), id);
    }
    return db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
  });

  const updated = trx();
  if(isMpesaMethod(method) || order.mpesa_account_id){
    const account = order.mpesa_account_id ? getMpesaAccountById(order.mpesa_account_id) : getDefaultMpesaAccountForBranch(order.branch_id);
    if(account){
      recordMpesaTransaction({
        user_id: account.user_id,
        account_id: account.id,
        branch_id: order.branch_id || null,
        order_id: order.id,
        phone_number: order.delivery_phone || order.contact || account.phone_number || "",
        amount: amount,
        reference: reference || "",
        mpesa_receipt: status === "Paid" ? (reference || "") : "",
        status: status === "Paid" ? "success" : "pending",
        result_desc: "Manual payment update",
        request_payload: req.body || {}
      });
    }
  }
  res.json(normalizeShopfrontOrder(updated));
});

// ===== Public Tracking (No Auth) =====
app.get("/api/shopfront/track/:id", (req, res) => {
  const id = Number(req.params.id);
  const contact = String(req.query.contact || "").trim();
  if(!id || !contact) return sendError(res, 400, "Order ID and contact required");
  const order = db.prepare("SELECT o.*, b.name as branch_name FROM shopfront_orders o LEFT JOIN branches b ON o.branch_id = b.id WHERE o.id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");
  const match = [order.contact, order.delivery_phone].filter(Boolean).some(val => String(val).toLowerCase() === contact.toLowerCase());
  if(!match) return sendError(res, 403, "Contact does not match this order");

  const payload = normalizeShopfrontOrder(order);
  delete payload.otp_code;
  res.json(payload);
});

// ===== Delivery Portal =====
app.get("/api/delivery/orders/available", authMiddleware, requireRole(["rider","admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  let where = "WHERE delivery_type = 'door' AND (assigned_rider_id IS NULL OR assigned_rider_id = '') AND status = 'Ready for Delivery'";
  if(branchId){
    where += " AND branch_id = ?";
    params.push(branchId);
  }
  const rows = db.prepare(`SELECT * FROM shopfront_orders ${where} ORDER BY created_at ASC`).all(...params);
  res.json(rows.map(r => normalizeShopfrontOrder(r)));
});

app.get("/api/delivery/orders/mine", authMiddleware, requireRole(["rider","admin","manager","supervisor"]), (req, res) => {
  const userId = req.user.id;
  const rows = db.prepare(`SELECT * FROM shopfront_orders WHERE assigned_rider_id = ? ORDER BY created_at DESC`).all(userId);
  res.json(rows.map(r => normalizeShopfrontOrder(r)));
});

app.post("/api/delivery/orders/:id/accept", authMiddleware, requireRole(["rider"]), (req, res) => {
  const id = Number(req.params.id);
  const order = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");
  if(order.delivery_type !== "door") return sendError(res, 400, "Not a delivery order");
  if(order.assigned_rider_id) return sendError(res, 400, "Order already assigned");
  if(order.status !== "Ready for Delivery") return sendError(res, 400, "Order not ready for delivery");

  const updated = updateOrderStatus(id, "Rider Accepted", {
    assigned_rider_id: req.user.id,
    assigned_rider_name: req.user.name
  });

  notifyUsersByRoles(
    ["admin","manager","supervisor"],
    { type: "Delivery", title: "Rider Assigned", message: `Order #${order.id} accepted by ${req.user.name}.`, link: "delivery.html" },
    order.branch_id || null
  );

  res.json(normalizeShopfrontOrder(updated));
});

app.post("/api/delivery/orders/:id/status", authMiddleware, requireRole(["rider","admin","manager","supervisor"]), (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body || {};
  if(!status) return sendError(res, 400, "Status required");
  const order = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");

  const allowed = ["Picked Up", "On the Way"];
  if(!allowed.includes(status)) return sendError(res, 400, "Invalid status");

  if(req.user.role === "rider" && Number(order.assigned_rider_id) !== Number(req.user.id)){
    return sendError(res, 403, "Not assigned to you");
  }

  const updated = updateOrderStatus(id, status);
  const normalized = normalizeShopfrontOrder(updated);
  const template = {
    subject: "Order Update - #{{orderId}}",
    text: "Order #{{orderId}} status changed to {{status}}. Track here: {{trackUrl}}.",
    html: "<p>Your order <strong>#{{orderId}}</strong> status is now <strong>{{status}}</strong>.</p><p>Track here: <a href=\"{{trackUrl}}\">{{trackUrl}}</a></p>"
  };
  notifyOrderByEmail(normalized, template);
  res.json(normalized);
});

app.post("/api/delivery/orders/:id/confirm", authMiddleware, requireRole(["rider","admin","manager","supervisor"]), (req, res) => {
  const id = Number(req.params.id);
  const { otp_code } = req.body || {};
  const order = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
  if(!order) return sendError(res, 404, "Order not found");

  if(req.user.role === "rider" && Number(order.assigned_rider_id) !== Number(req.user.id)){
    return sendError(res, 403, "Not assigned to you");
  }

  if(order.otp_code && req.user.role === "rider"){
    if(String(order.otp_code) !== String(otp_code || "")){
      return sendError(res, 400, "Invalid OTP");
    }
  }

  const methodLower = String(order.payment_method || "").toLowerCase();
  const isCashOnDelivery = methodLower.includes("cash") || methodLower.includes("pay on") || methodLower.includes("delivery");
  const paymentExtra = {};
  if(isCashOnDelivery && order.payment_status !== "Paid"){
    paymentExtra.payment_status = "Paid";
    paymentExtra.paid_amount = Number(order.total || 0);
    paymentExtra.paid_at = now();
    if(!order.payment_reference){
      paymentExtra.payment_reference = "COD";
    }
  }

  let updated = updateOrderStatus(id, "Delivered", { delivered_at: now(), ...paymentExtra });
  if(paymentExtra.payment_status === "Paid"){
    const refreshed = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
    const timeline = ensureTimeline(refreshed, "Payment Confirmed");
    db.prepare("UPDATE shopfront_orders SET tracking_timeline = ?, updated_at = ? WHERE id = ?")
      .run(JSON.stringify(timeline), now(), id);
    updated = db.prepare("SELECT * FROM shopfront_orders WHERE id = ?").get(id);
  }

  notifyUsersByRoles(
    ["admin","manager","supervisor"],
    { type: "Delivery", title: "Order Delivered", message: `Order #${order.id} delivered.`, link: "shopfront.html" },
    order.branch_id || null
  );

  const normalized = normalizeShopfrontOrder(updated);
  const template = {
    subject: "Order Delivered - #{{orderId}}",
    text: "Order #{{orderId}} has been delivered. Track here: {{trackUrl}}.",
    html: "<p>Your order <strong>#{{orderId}}</strong> has been delivered.</p><p>Track here: <a href=\"{{trackUrl}}\">{{trackUrl}}</a></p>"
  };
  notifyOrderByEmail(normalized, template);
  res.json(normalized);
});

// ===== Kitchen Display =====
app.get("/api/kitchen/orders", authMiddleware, requireRole(["admin","manager","supervisor","storekeeper","cashier"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  const where = branchId ? "WHERE s.branch_id = ?" : "";
  if(branchId) params.push(branchId);
  const sales = db.prepare(`SELECT s.id,s.receipt_id,s.created_at,s.branch_id FROM sales s ${where} ORDER BY s.created_at DESC LIMIT 20`).all(...params);
  if(sales.length === 0) return res.json([]);
  const ids = sales.map(s => s.id);
  const placeholders = ids.map(() => "?").join(",");
  const items = db.prepare(`SELECT sale_id, product_name, qty FROM sale_items WHERE sale_id IN (${placeholders})`).all(...ids);
  const map = {};
  sales.forEach(s => { map[s.id] = { ...s, items: [] }; });
  items.forEach(it => { if(map[it.sale_id]) map[it.sale_id].items.push({ name: it.product_name, qty: it.qty }); });
  res.json(Object.values(map));
});

// ===== Suppliers =====
app.get("/api/suppliers", authMiddleware, (req, res) => {
  const rows = db.prepare("SELECT * FROM suppliers ORDER BY name ASC").all();
  res.json(rows);
});

app.post("/api/suppliers", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { name, contact, phone, email, address, lead_time, status } = req.body || {};
  if(!name || !phone || !email) return sendError(res, 400, "Name, phone, email required");

  const exists = db.prepare("SELECT id FROM suppliers WHERE name = ?").get(name);
  if(exists) return sendError(res, 400, "Supplier already exists");

  const stmt = db.prepare(`INSERT INTO suppliers (name,contact,phone,email,address,lead_time,status,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?)`);
  const info = stmt.run(name, contact || "", phone, email, address || "", lead_time ?? null, status || "active", now(), now());
  res.json({ id: info.lastInsertRowid });
});

app.put("/api/suppliers/:id", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM suppliers WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Supplier not found");

  const { name, contact, phone, email, address, lead_time, status } = req.body || {};
  const newName = name || existing.name;
  const newContact = contact ?? existing.contact;
  const newPhone = phone || existing.phone;
  const newEmail = email || existing.email;
  const newAddress = address ?? existing.address;
  const newLead = lead_time ?? existing.lead_time;
  const newStatus = status || existing.status;

  db.prepare(`UPDATE suppliers SET name=?, contact=?, phone=?, email=?, address=?, lead_time=?, status=?, updated_at=? WHERE id=?`)
    .run(newName, newContact, newPhone, newEmail, newAddress, newLead, newStatus, now(), id);

  res.json({ success: true });
});

app.delete("/api/suppliers/:id", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM suppliers WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Supplier not found");

  db.prepare("UPDATE products SET supplier_id = NULL WHERE supplier_id = ?").run(id);
  db.prepare("DELETE FROM suppliers WHERE id = ?").run(id);
  res.json({ success: true });
});

// ===== Products =====
app.get("/api/products", authMiddleware, (req, res) => {
  const branchId = resolveBranchId(req);
  const { limit, offset } = parsePagination(req, 2000);
  if(isVendorRole(req.user.role)){
    const rows = db.prepare(`
      SELECT p.*, s.name as supplier_name, s.lead_time as supplier_lead_time, b.name as branch_name,
             w.name as warehouse_name,
             COALESCE(pp.price, p.price) as effective_price,
             COALESCE(pp.cost_price, p.cost_price) as effective_cost
      FROM products p
      LEFT JOIN suppliers s ON p.supplier_id = s.id
      LEFT JOIN branches b ON p.branch_id = b.id
      LEFT JOIN warehouses w ON p.warehouse_id = w.id
      LEFT JOIN product_prices pp ON pp.product_id = p.id AND pp.branch_id = p.branch_id
      WHERE p.owner_user_id = ?
      ORDER BY p.id DESC
      ${limit ? "LIMIT ? OFFSET ?" : ""}
    `).all(...(limit ? [req.user.id, limit, offset] : [req.user.id]));
    return res.json(rows);
  }
  if(branchId){
    const rows = db.prepare(`
      SELECT p.*, s.name as supplier_name, s.lead_time as supplier_lead_time, b.name as branch_name,
             w.name as warehouse_name,
             COALESCE(pp.price, p.price) as effective_price,
             COALESCE(pp.cost_price, p.cost_price) as effective_cost
      FROM products p
      LEFT JOIN suppliers s ON p.supplier_id = s.id
      LEFT JOIN branches b ON p.branch_id = b.id
      LEFT JOIN warehouses w ON p.warehouse_id = w.id
      LEFT JOIN product_prices pp ON pp.product_id = p.id AND pp.branch_id = ?
      WHERE p.branch_id = ?
      ORDER BY p.id DESC
      ${limit ? "LIMIT ? OFFSET ?" : ""}
    `).all(...(limit ? [branchId, branchId, limit, offset] : [branchId, branchId]));
    return res.json(rows);
  }
  const rows = db.prepare(`
    SELECT p.*, s.name as supplier_name, s.lead_time as supplier_lead_time, b.name as branch_name,
           w.name as warehouse_name,
           p.price as effective_price, p.cost_price as effective_cost
    FROM products p
    LEFT JOIN suppliers s ON p.supplier_id = s.id
    LEFT JOIN branches b ON p.branch_id = b.id
    LEFT JOIN warehouses w ON p.warehouse_id = w.id
    ORDER BY p.id DESC
    ${limit ? "LIMIT ? OFFSET ?" : ""}
  `).all(...(limit ? [limit, offset] : []));
  res.json(rows);
});

app.post("/api/products", authMiddleware, requireRole(["admin","manager","supplier","seller","retailer","wholesaler"]), (req, res) => {
  let { name, category, price, cost_price, quantity, supplier_id, reorder_level, min_stock, max_stock, safety_stock, lead_time, barcode, branch_id, batch_no, expiry_date, warehouse_id, is_published } = req.body || {};
  if(!name || price == null) return sendError(res, 400, "Name and price required");

  const branchId = isVendorRole(req.user.role)
    ? Number(req.user.branch_id)
    : (branch_id ? Number(branch_id) : resolveBranchIdFromBody(req));
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");
  if(isVendorRole(req.user.role) && req.user.branch_id && Number(req.user.branch_id) !== Number(branchId)){
    return sendError(res, 403, "Vendors can only use their assigned branch");
  }
  const warehouseId = warehouse_id ? Number(warehouse_id) : null;
  if(warehouseId){
    const warehouse = getWarehouseById(warehouseId);
    if(!warehouse) return sendError(res, 400, "Warehouse not found");
    if(warehouse.branch_id && Number(warehouse.branch_id) !== Number(branchId)){
      return sendError(res, 400, "Warehouse not in selected branch");
    }
  }

  const minStock = min_stock !== undefined && min_stock !== null && min_stock !== "" ? Number(min_stock) : null;
  const maxStock = max_stock !== undefined && max_stock !== null && max_stock !== "" ? Number(max_stock) : null;
  const safetyStock = safety_stock !== undefined && safety_stock !== null && safety_stock !== "" ? Number(safety_stock) : null;
  if(minStock !== null && (!Number.isFinite(minStock) || minStock < 0)) return sendError(res, 400, "Invalid min stock");
  if(maxStock !== null && (!Number.isFinite(maxStock) || maxStock < 0)) return sendError(res, 400, "Invalid max stock");
  if(safetyStock !== null && (!Number.isFinite(safetyStock) || safetyStock < 0)) return sendError(res, 400, "Invalid safety stock");

  const finalBarcode = barcode || generateUniqueBarcode();
  const barcodeExists = db.prepare("SELECT id FROM products WHERE barcode = ?").get(finalBarcode);
  if(barcodeExists) return sendError(res, 400, "Barcode already exists");

  const published = is_published === undefined || is_published === null ? 1 : (Number(is_published) ? 1 : 0);
  const ownerUserId = isVendorRole(req.user.role) ? req.user.id : null;
  const stmt = db.prepare(`INSERT INTO products (name,category,price,cost_price,quantity,is_published,owner_user_id,supplier_id,branch_id,warehouse_id,reorder_level,min_stock,max_stock,safety_stock,lead_time,barcode,batch_no,expiry_date,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const info = stmt.run(
    name,
    category || "",
    Number(price),
    Number(cost_price || 0),
    Number(quantity || 0),
    published,
    ownerUserId,
    supplier_id || null,
    branchId,
    warehouseId,
    reorder_level ?? null,
    minStock,
    maxStock,
    safetyStock,
    lead_time ?? null,
    finalBarcode,
    batch_no || null,
    expiry_date || null,
    now(),
    now()
  );
  logActivity(req.user, "product_create", "products", info.lastInsertRowid, `Product ${name}`, branchId);
  res.json({ id: info.lastInsertRowid });
});

app.put("/api/products/:id", authMiddleware, requireRole(["admin","manager","supplier","seller","retailer","wholesaler"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM products WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Product not found");
  if(isVendorRole(req.user.role) && Number(existing.owner_user_id) !== Number(req.user.id)){
    return sendError(res, 403, "You can only edit your own products");
  }

  let { name, category, price, cost_price, quantity, supplier_id, reorder_level, min_stock, max_stock, safety_stock, lead_time, barcode, branch_id, batch_no, expiry_date, warehouse_id, is_published } = req.body || {};
  const newBarcode = barcode || existing.barcode;
  const newBranch = isVendorRole(req.user.role)
    ? existing.branch_id
    : (branch_id !== undefined && branch_id !== null && branch_id !== "" ? Number(branch_id) : existing.branch_id);
  if(newBranch && !getBranchById(newBranch)) return sendError(res, 400, "Branch not found");
  const newWarehouse = warehouse_id !== undefined && warehouse_id !== null && warehouse_id !== "" ? Number(warehouse_id) : existing.warehouse_id;
  if(newWarehouse){
    const warehouse = getWarehouseById(newWarehouse);
    if(!warehouse) return sendError(res, 400, "Warehouse not found");
    if(warehouse.branch_id && newBranch && Number(warehouse.branch_id) !== Number(newBranch)){
      return sendError(res, 400, "Warehouse not in selected branch");
    }
  }

  const minStock = min_stock !== undefined && min_stock !== null && min_stock !== "" ? Number(min_stock) : existing.min_stock;
  const maxStock = max_stock !== undefined && max_stock !== null && max_stock !== "" ? Number(max_stock) : existing.max_stock;
  const safetyStock = safety_stock !== undefined && safety_stock !== null && safety_stock !== "" ? Number(safety_stock) : existing.safety_stock;
  if(minStock !== null && (!Number.isFinite(Number(minStock)) || Number(minStock) < 0)) return sendError(res, 400, "Invalid min stock");
  if(maxStock !== null && (!Number.isFinite(Number(maxStock)) || Number(maxStock) < 0)) return sendError(res, 400, "Invalid max stock");
  if(safetyStock !== null && (!Number.isFinite(Number(safetyStock)) || Number(safetyStock) < 0)) return sendError(res, 400, "Invalid safety stock");

  if(newBarcode !== existing.barcode){
    const dup = db.prepare("SELECT id FROM products WHERE barcode = ?").get(newBarcode);
    if(dup) return sendError(res, 400, "Barcode already exists");
  }

  const published = is_published === undefined || is_published === null ? existing.is_published : (Number(is_published) ? 1 : 0);
  db.prepare(`UPDATE products SET name=?, category=?, price=?, cost_price=?, quantity=?, is_published=?, supplier_id=?, branch_id=?, warehouse_id=?, reorder_level=?, min_stock=?, max_stock=?, safety_stock=?, lead_time=?, barcode=?, batch_no=?, expiry_date=?, updated_at=? WHERE id=?`)
    .run(
      name || existing.name,
      category ?? existing.category,
      price != null ? Number(price) : existing.price,
      cost_price != null ? Number(cost_price) : existing.cost_price,
      quantity != null ? Number(quantity) : existing.quantity,
      published,
      supplier_id ?? existing.supplier_id,
      newBranch,
      newWarehouse,
      reorder_level ?? existing.reorder_level,
      minStock,
      maxStock,
      safetyStock,
      lead_time ?? existing.lead_time,
      newBarcode,
      batch_no ?? existing.batch_no,
      expiry_date ?? existing.expiry_date,
      now(),
      id
    );

  logActivity(req.user, "product_update", "products", id, `Product ${existing.name} updated`, newBranch);
  res.json({ success: true });
});

app.delete("/api/products/:id", authMiddleware, requireRole(["admin","manager","supplier","seller","retailer","wholesaler"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM products WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Product not found");
  if(isVendorRole(req.user.role) && Number(existing.owner_user_id) !== Number(req.user.id)){
    return sendError(res, 403, "You can only delete your own products");
  }

  db.prepare("UPDATE sale_items SET product_id = NULL WHERE product_id = ?").run(id);
  db.prepare("UPDATE purchase_orders SET product_id = NULL WHERE product_id = ?").run(id);
  db.prepare("DELETE FROM products WHERE id = ?").run(id);

  res.json({ success: true });
});

app.post("/api/products/bulk-delete", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { ids } = req.body || {};
  if(!Array.isArray(ids) || ids.length === 0) return sendError(res, 400, "Product IDs required");
  const cleanIds = ids.map(id => Number(id)).filter(id => Number.isFinite(id));
  if(cleanIds.length === 0) return sendError(res, 400, "Invalid product IDs");

  const placeholders = cleanIds.map(() => "?").join(",");
  const rows = db.prepare(`SELECT id, branch_id FROM products WHERE id IN (${placeholders})`).all(...cleanIds);
  if(rows.length !== cleanIds.length) return sendError(res, 404, "Some products not found");

  const branchId = resolveBranchIdFromBody(req) || resolveBranchId(req);
  if(branchId){
    const invalid = rows.find(r => r.branch_id && Number(r.branch_id) !== Number(branchId));
    if(invalid) return sendError(res, 403, "Some products are not in the selected branch");
  }

  const trx = db.transaction(() => {
    cleanIds.forEach(id => {
      db.prepare("UPDATE sale_items SET product_id = NULL WHERE product_id = ?").run(id);
      db.prepare("UPDATE purchase_orders SET product_id = NULL WHERE product_id = ?").run(id);
      db.prepare("DELETE FROM products WHERE id = ?").run(id);
    });
  });
  trx();

  logActivity(req.user, "product_bulk_delete", "products", null, `Deleted ${cleanIds.length} products`, branchId || null);
  res.json({ success: true, deleted: cleanIds.length });
});

// ===== Bulk Barcode Generation =====
app.post("/api/products/barcodes/generate", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const branchId = req.body && req.body.branch_id ? Number(req.body.branch_id) : resolveBranchIdFromBody(req);
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");

  const rows = db.prepare("SELECT id FROM products WHERE branch_id = ? AND (barcode IS NULL OR barcode = '')").all(branchId);
  const stmt = db.prepare("UPDATE products SET barcode = ?, updated_at = ? WHERE id = ?");
  let updated = 0;
  rows.forEach(r => {
    const code = generateUniqueBarcode();
    stmt.run(code, now(), r.id);
    updated++;
  });
  logActivity(req.user, "barcode_generate", "products", null, `Generated ${updated} barcodes`, branchId);
  res.json({ updated });
});

// ===== Product Price Overrides =====
app.get("/api/product-prices", authMiddleware, (req, res) => {
  const { product_id, branch_id } = req.query;
  const clauses = [];
  const params = [];
  if(product_id){ clauses.push("pp.product_id = ?"); params.push(Number(product_id)); }
  if(branch_id && branch_id !== "all"){ clauses.push("pp.branch_id = ?"); params.push(Number(branch_id)); }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = db.prepare(`
    SELECT pp.*, b.name as branch_name, p.name as product_name
    FROM product_prices pp
    LEFT JOIN branches b ON pp.branch_id = b.id
    LEFT JOIN products p ON pp.product_id = p.id
    ${where}
    ORDER BY pp.updated_at DESC
  `).all(...params);
  res.json(rows);
});

app.post("/api/product-prices", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { product_id, branch_id, price, cost_price } = req.body || {};
  if(!product_id || !branch_id || price == null) return sendError(res, 400, "Missing fields");
  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(product_id);
  if(!product) return sendError(res, 404, "Product not found");
  if(!getBranchById(branch_id)) return sendError(res, 400, "Branch not found");

  const existing = db.prepare("SELECT id FROM product_prices WHERE product_id = ? AND branch_id = ?").get(product_id, branch_id);
  if(existing){
    db.prepare("UPDATE product_prices SET price=?, cost_price=?, updated_at=? WHERE id=?")
      .run(Number(price), Number(cost_price || 0), now(), existing.id);
    return res.json({ id: existing.id, updated: true });
  }
  const info = db.prepare(`INSERT INTO product_prices (product_id,branch_id,price,cost_price,created_at,updated_at)
    VALUES (?,?,?,?,?,?)`)
    .run(product_id, branch_id, Number(price), Number(cost_price || 0), now(), now());
  res.json({ id: info.lastInsertRowid });
});

app.delete("/api/product-prices/:id", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM product_prices WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Override not found");
  db.prepare("DELETE FROM product_prices WHERE id = ?").run(id);
  res.json({ success: true });
});

// ===== Product CSV Import =====
app.post("/api/products/import", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { csv, branch_id } = req.body || {};
  if(!csv) return sendError(res, 400, "CSV data required");
  const branchId = branch_id ? Number(branch_id) : resolveBranchIdFromBody(req);
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");

  const rows = parseCsv(csv);
  if(rows.length < 2) return sendError(res, 400, "CSV must include headers and at least one row");
  const headers = rows[0].map(h => h.trim().toLowerCase());
  let created = 0;
  let updated = 0;
  const errors = [];

  for(let i=1;i<rows.length;i++){
    const row = rows[i];
    const data = {};
    headers.forEach((h, idx) => { data[h] = (row[idx] || "").trim(); });
    const name = data.name || data.product || data.item;
    if(!name){ errors.push({ row: i+1, error: "Missing name" }); continue; }
    const price = Number(data.price || data.selling_price || 0);
    const cost = Number(data.cost_price || data.cost || 0);
    const quantity = Number(data.quantity || data.qty || 0);
    const category = data.category || "";
    const barcode = data.barcode || "";
    const reorder = data.reorder_level ? Number(data.reorder_level) : null;
    const minStock = data.min_stock ? Number(data.min_stock) : null;
    const maxStock = data.max_stock ? Number(data.max_stock) : null;
    const safetyStock = data.safety_stock ? Number(data.safety_stock) : null;
    const lead = data.lead_time ? Number(data.lead_time) : null;
    const batchNo = data.batch_no || data.batch || null;
    const expiry = data.expiry_date || data.expiry || null;
    const publishedRaw = data.is_published ?? data.published ?? data.visible ?? null;
    const published = publishedRaw === null || publishedRaw === undefined || publishedRaw === "" ? 1 : (Number(publishedRaw) ? 1 : 0);
    const supplierName = data.supplier || data.supplier_name || "";
    const warehouseName = data.warehouse || data.warehouse_name || "";

    let supplierId = null;
    if(supplierName){
      const existingSupplier = db.prepare("SELECT id FROM suppliers WHERE name = ?").get(supplierName);
      if(existingSupplier) supplierId = existingSupplier.id;
      else{
        const info = db.prepare(`INSERT INTO suppliers (name,contact,phone,email,address,lead_time,status,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?)`)
          .run(supplierName, "", "", "", "", null, "active", now(), now());
        supplierId = info.lastInsertRowid;
      }
    }

    let warehouseId = null;
    if(warehouseName){
      const existingWarehouse = db.prepare("SELECT id FROM warehouses WHERE name = ? AND branch_id = ?").get(warehouseName, branchId);
      if(existingWarehouse) warehouseId = existingWarehouse.id;
      else{
        const info = db.prepare(`INSERT INTO warehouses (name,location,capacity,status,branch_id,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?)`)
          .run(warehouseName, "", null, "active", branchId, now(), now());
        warehouseId = info.lastInsertRowid;
      }
    }

    let existing = null;
    if(barcode){
      existing = db.prepare("SELECT * FROM products WHERE barcode = ?").get(barcode);
    }
    if(!existing){
      existing = db.prepare("SELECT * FROM products WHERE name = ? AND branch_id = ?").get(name, branchId);
    }

    if(existing){
      db.prepare(`UPDATE products SET category=?, price=?, cost_price=?, quantity=?, is_published=?, supplier_id=?, warehouse_id=?, reorder_level=?, min_stock=?, max_stock=?, safety_stock=?, lead_time=?, barcode=?, batch_no=?, expiry_date=?, updated_at=? WHERE id=?`)
        .run(category || existing.category, price || existing.price, cost || existing.cost_price, quantity, published, supplierId ?? existing.supplier_id, warehouseId ?? existing.warehouse_id, reorder ?? existing.reorder_level, minStock ?? existing.min_stock, maxStock ?? existing.max_stock, safetyStock ?? existing.safety_stock, lead ?? existing.lead_time, barcode || existing.barcode, batchNo ?? existing.batch_no, expiry ?? existing.expiry_date, now(), existing.id);
      updated++;
    }else{
      const finalBarcode = barcode || generateUniqueBarcode();
      db.prepare(`INSERT INTO products (name,category,price,cost_price,quantity,is_published,supplier_id,branch_id,warehouse_id,reorder_level,min_stock,max_stock,safety_stock,lead_time,barcode,batch_no,expiry_date,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(name, category, price || 0, cost || 0, quantity, published, supplierId, branchId, warehouseId, reorder, minStock, maxStock, safetyStock, lead, finalBarcode, batchNo, expiry, now(), now());
      created++;
    }
  }

  logActivity(req.user, "import", "products", null, `CSV import: ${created} created, ${updated} updated`, branchId);
  res.json({ created, updated, errors });
});

// ===== Customers =====
app.get("/api/customers", authMiddleware, (req, res) => {
  const { limit, offset } = parsePagination(req, 2000);
  const rows = db.prepare(`SELECT * FROM customers ORDER BY id DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
    .all(...(limit ? [limit, offset] : []));
  res.json(rows);
});

app.post("/api/customers", authMiddleware, (req, res) => {
  const { name, phone, email, address } = req.body || {};
  if(!name || !phone) return sendError(res, 400, "Name and phone required");
  const stmt = db.prepare(`INSERT INTO customers (name,phone,email,address,created_at,updated_at)
    VALUES (?,?,?,?,?,?)`);
  const info = stmt.run(name, phone, email || "", address || "", now(), now());
  res.json({ id: info.lastInsertRowid });
});

app.put("/api/customers/:id", authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM customers WHERE id = ?").get(id);
  if(!existing) return sendError(res, 404, "Customer not found");

  const { name, phone, email, address } = req.body || {};
  db.prepare(`UPDATE customers SET name=?, phone=?, email=?, address=?, updated_at=? WHERE id=?`)
    .run(
      name || existing.name,
      phone || existing.phone,
      email ?? existing.email,
      address ?? existing.address,
      now(),
      id
    );
  res.json({ success: true });
});

app.delete("/api/customers/:id", authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  db.prepare("DELETE FROM customers WHERE id = ?").run(id);
  res.json({ success: true });
});

// ===== Inventory Movements =====
app.get("/api/movements", authMiddleware, (req, res) => {
  const branchId = resolveBranchId(req);
  const { limit, offset } = parsePagination(req, 2000);
  const baseQuery = `
    SELECT m.*, b.name as branch_name
    FROM inventory_movements m
    LEFT JOIN branches b ON m.branch_id = b.id
  `;
  const rows = branchId
    ? db.prepare(`${baseQuery} WHERE m.branch_id = ? ORDER BY created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [branchId, limit, offset] : [branchId]))
    : db.prepare(`${baseQuery} ORDER BY created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [limit, offset] : []));
  res.json(rows);
});

app.post("/api/movements", authMiddleware, requireRole(["admin","manager","staff","storekeeper"]), (req, res) => {
  const { product_id, type, qty, reference, note, branch_id } = req.body || {};
  if(!product_id || !type || !qty) return sendError(res, 400, "Missing fields");

  const branchId = branch_id ? Number(branch_id) : resolveBranchIdFromBody(req);
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");

  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(product_id);
  if(!product) return sendError(res, 404, "Product not found");
  if(product.branch_id && Number(product.branch_id) !== Number(branchId)) return sendError(res, 400, "Product is not in selected branch");

  const currentQty = Number(product.quantity) || 0;
  if(type === "OUT" && qty > currentQty) return sendError(res, 400, "Not enough stock");

  const newQty = type === "IN" ? currentQty + Number(qty) : currentQty - Number(qty);
  db.prepare("UPDATE products SET quantity=?, updated_at=? WHERE id=?").run(newQty, now(), product_id);

  db.prepare(`INSERT INTO inventory_movements (product_id,product_name,type,qty,reference,note,user_id,user_name,branch_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(product_id, product.name, type, qty, reference || "-", note || "", req.user.id, req.user.name, branchId, now());

  logActivity(req.user, "inventory_movement", "inventory_movements", null, `${type} ${qty} ${product.name}`, branchId);
  const threshold = getReorderThreshold(product);
  if(Number(newQty) <= Number(threshold)){
    notifyUsersByRoles(
      ["admin","manager","storekeeper","supervisor"],
      {
        type: "Inventory",
        title: "Low Stock Alert",
        message: `${product.name} has dropped to ${newQty} units (threshold ${threshold}).`,
        link: "inventory.html"
      },
      branchId
    );
  }
  res.json({ success: true, newQty });
});

// ===== Purchase Orders =====
app.get("/api/purchase-orders", authMiddleware, (req, res) => {
  const branchId = resolveBranchId(req);
  const { limit, offset } = parsePagination(req, 2000);
  const baseQuery = `
    SELECT po.*, b.name as branch_name
    FROM purchase_orders po
    LEFT JOIN branches b ON po.branch_id = b.id
  `;
  const rows = branchId
    ? db.prepare(`${baseQuery} WHERE po.branch_id = ? ORDER BY po.created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [branchId, limit, offset] : [branchId]))
    : db.prepare(`${baseQuery} ORDER BY po.created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [limit, offset] : []));
  res.json(rows);
});

app.post("/api/purchase-orders", authMiddleware, requireRole(["admin","manager"]), (req, res) => {
  const { supplier_id, product_id, qty, eta_date, branch_id } = req.body || {};
  if(!supplier_id || !product_id || !qty || !eta_date) return sendError(res, 400, "Missing fields");

  const branchId = branch_id ? Number(branch_id) : resolveBranchIdFromBody(req);
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");

  const supplier = db.prepare("SELECT * FROM suppliers WHERE id = ?").get(supplier_id);
  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(product_id);
  if(!supplier || !product) return sendError(res, 404, "Supplier or product not found");
  if(product.branch_id && Number(product.branch_id) !== Number(branchId)) return sendError(res, 400, "Product is not in selected branch");

  const poNumber = "PO" + Date.now();
  db.prepare(`INSERT INTO purchase_orders (po_number,supplier_id,supplier_name,product_id,product_name,branch_id,qty,eta_date,status,requested_by,requested_by_name,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(poNumber, supplier_id, supplier.name, product_id, product.name, branchId, qty, eta_date, "Pending", req.user.id, req.user.name, now());

  logActivity(req.user, "purchase_order", "purchase_orders", null, `PO ${poNumber} created`, branchId);
  notifyUsersByRoles(
    ["admin","manager","storekeeper","supervisor"],
    {
      type: "Inventory",
      title: "Purchase Order Created",
      message: `PO ${poNumber} created for ${product.name} (${qty} units).`,
      link: "inventory.html"
    },
    branchId
  );
  res.json({ success: true });
});

app.post("/api/purchase-orders/:id/receive", authMiddleware, requireRole(["admin","manager","staff","storekeeper"]), (req, res) => {
  const id = Number(req.params.id);
  const po = db.prepare("SELECT * FROM purchase_orders WHERE id = ?").get(id);
  if(!po) return sendError(res, 404, "PO not found");
  if(po.status === "Received") return sendError(res, 400, "Already received");

  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(po.product_id);
  if(!product) return sendError(res, 400, "Product not found for PO");
  if(po.branch_id && product.branch_id && Number(po.branch_id) !== Number(product.branch_id)) return sendError(res, 400, "PO branch mismatch");

  const newQty = (Number(product.quantity) || 0) + Number(po.qty);
  db.prepare("UPDATE products SET quantity=?, updated_at=? WHERE id=?").run(newQty, now(), product.id);

  db.prepare("UPDATE purchase_orders SET status='Received', received_at=? WHERE id=?").run(now(), id);

  db.prepare(`INSERT INTO inventory_movements (product_id,product_name,type,qty,reference,note,user_id,user_name,branch_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(product.id, product.name, "IN", po.qty, po.po_number, "PO received", req.user.id, req.user.name, po.branch_id || product.branch_id || null, now());

  logActivity(req.user, "purchase_order_receive", "purchase_orders", po.id, `PO ${po.po_number} received`, po.branch_id || product.branch_id || null);
  notifyUsersByRoles(
    ["admin","manager","storekeeper","supervisor"],
    {
      type: "Inventory",
      title: "Purchase Order Received",
      message: `PO ${po.po_number} received. Stock updated for ${product.name}.`,
      link: "inventory.html"
    },
    po.branch_id || product.branch_id || null
  );
  res.json({ success: true, newQty });
});

// ===== Sales =====
app.get("/api/sales", authMiddleware, (req, res) => {
  const branchId = resolveBranchId(req);
  const { limit, offset } = parsePagination(req, 2000);
  const baseQuery = `
    SELECT s.*, b.name as branch_name
    FROM sales s
    LEFT JOIN branches b ON s.branch_id = b.id
  `;
  const rows = branchId
    ? db.prepare(`${baseQuery} WHERE s.branch_id = ? ORDER BY s.created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [branchId, limit, offset] : [branchId]))
    : db.prepare(`${baseQuery} ORDER BY s.created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [limit, offset] : []));
  res.json(rows);
});

app.get("/api/sales/:id", authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const sale = db.prepare("SELECT * FROM sales WHERE id = ?").get(id);
  if(!sale) return sendError(res, 404, "Sale not found");
  const items = db.prepare("SELECT * FROM sale_items WHERE sale_id = ?").all(id);
  res.json({ sale, items });
});

app.get("/api/sales/receipt/:receiptId", authMiddleware, (req, res) => {
  const receiptId = req.params.receiptId;
  const sale = db.prepare("SELECT * FROM sales WHERE receipt_id = ?").get(receiptId);
  if(!sale) return sendError(res, 404, "Sale not found");
  const items = db.prepare(`
    SELECT si.*, p.barcode
    FROM sale_items si
    LEFT JOIN products p ON p.id = si.product_id
    WHERE si.sale_id = ?
  `).all(sale.id);
  res.json({ sale, items });
});

app.get("/api/sale-items", authMiddleware, (req, res) => {
  const branchId = resolveBranchId(req);
  const { limit, offset } = parsePagination(req, 2000);
  const baseQuery = `
    SELECT si.product_name, si.qty, s.created_at, s.branch_id
    FROM sale_items si
    JOIN sales s ON s.id = si.sale_id
  `;
  const items = branchId
    ? db.prepare(`${baseQuery} WHERE s.branch_id = ? ORDER BY s.created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [branchId, limit, offset] : [branchId]))
    : db.prepare(`${baseQuery} ORDER BY s.created_at DESC ${limit ? "LIMIT ? OFFSET ?" : ""}`)
        .all(...(limit ? [limit, offset] : []));
  res.json(items);
});

app.post("/api/sales", authMiddleware, requireRole(["admin","manager","cashier","staff"]), (req, res) => {
  const { customer_id, items, discount, tax, branch_id, payment_mode, fees, table_name } = req.body || {};
  if(!items || !Array.isArray(items) || items.length === 0) return sendError(res, 400, "Items required");

  const branchId = branch_id ? Number(branch_id) : resolveBranchIdFromBody(req);
  if(!branchId) return sendError(res, 400, "Branch required");
  if(!getBranchById(branchId)) return sendError(res, 400, "Branch not found");
  const settings = getSettingsForBranch(branchId || 0);

  let subtotal = 0;
  const preparedItems = [];
  for(const item of items){
    const product = db.prepare("SELECT * FROM products WHERE id = ?").get(item.product_id);
    if(!product) return sendError(res, 404, "Product not found");
    if(product.branch_id && Number(product.branch_id) !== Number(branchId)) return sendError(res, 400, `Product ${product.name} is not in selected branch`);
    if(Number(item.qty) > Number(product.quantity)) return sendError(res, 400, `Not enough stock for ${product.name}`);
    let effectivePrice = Number(product.price);
    let effectiveCost = Number(product.cost_price || 0);
    const override = db.prepare("SELECT price, cost_price FROM product_prices WHERE product_id = ? AND branch_id = ?")
      .get(product.id, branchId);
    if(override){
      if(override.price != null) effectivePrice = Number(override.price);
      if(override.cost_price != null) effectiveCost = Number(override.cost_price);
    }
    const lineSubtotal = effectivePrice * Number(item.qty);
    subtotal += lineSubtotal;
    preparedItems.push({
      product,
      qty: Number(item.qty),
      price: effectivePrice,
      cost_price: effectiveCost,
      subtotal: lineSubtotal
    });
  }

  const discountAmt = Number.isFinite(Number(discount)) ? Number(discount) : Number(settings.discount_default || 0);
  const taxRate = Number.isFinite(Number(tax)) ? Number(tax) : Number(settings.tax_rate_default || 0);
  const taxable = Math.max(0, subtotal - discountAmt);
  const taxAmt = taxable * (taxRate / 100);
  const feeObj = fees && typeof fees === "object" ? fees : {};
  const feesTotal =
    (Number(feeObj.delivery) || 0) +
    (Number(feeObj.packing) || 0) +
    (Number(feeObj.service) || 0) +
    (Number(feeObj.other) || 0);
  let total = taxable + taxAmt + feesTotal;
  if(settings.round_off_enabled){
    total = Math.round(total);
  }

  const customer = customer_id ? db.prepare("SELECT * FROM customers WHERE id = ?").get(customer_id) : null;
  const prefix = settings.receipt_prefix || "RCPT";
  const receiptId = `${prefix}${Date.now()}`;
  const paymentMode = payment_mode || (Array.isArray(settings.payment_modes) && settings.payment_modes[0]) || "Cash";
  const tableName = table_name || null;

  const insertSale = db.prepare(`INSERT INTO sales (receipt_id,customer_id,customer_name,cashier_id,cashier_name,branch_id,payment_mode,subtotal,discount,tax,fees_total,fees_breakdown,table_name,total,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

  const insertItem = db.prepare(`INSERT INTO sale_items (sale_id,product_id,product_name,qty,price,cost_price,subtotal)
    VALUES (?,?,?,?,?,?,?)`);

  const updateProduct = db.prepare("UPDATE products SET quantity=?, updated_at=? WHERE id=?");
  const insertMove = db.prepare(`INSERT INTO inventory_movements (product_id,product_name,type,qty,reference,note,user_id,user_name,branch_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);

  const lowStockAlerts = [];
  preparedItems.forEach(item => {
    const projected = Number(item.product.quantity) - item.qty;
    const threshold = getReorderThreshold(item.product);
    if(projected <= threshold){
      lowStockAlerts.push({ product: item.product, projected, threshold });
    }
  });

  const trx = db.transaction(() => {
    const saleInfo = insertSale.run(
      receiptId,
      customer ? customer.id : null,
      customer ? customer.name : "Walk-in",
      req.user.id,
      req.user.name,
      branchId,
      paymentMode,
      subtotal,
      discountAmt,
      taxAmt,
      feesTotal,
      JSON.stringify({ delivery: Number(feeObj.delivery) || 0, packing: Number(feeObj.packing) || 0, service: Number(feeObj.service) || 0, other: Number(feeObj.other) || 0 }),
      tableName,
      total,
      now()
    );

    preparedItems.forEach(item => {
      insertItem.run(
        saleInfo.lastInsertRowid,
        item.product.id,
        item.product.name,
        item.qty,
        item.price,
        item.cost_price,
        item.subtotal
      );

      const newQty = Number(item.product.quantity) - item.qty;
      updateProduct.run(newQty, now(), item.product.id);

      insertMove.run(
        item.product.id,
        item.product.name,
        "OUT",
        item.qty,
        receiptId,
        "Sale",
        req.user.id,
        req.user.name,
        branchId,
        now()
      );
    });

    return saleInfo.lastInsertRowid;
  });

  const saleId = trx();
  logActivity(req.user, "sale", "sales", saleId, `Receipt ${receiptId}`, branchId);
  if(total >= 50000){
    notifyUsersByRoles(
      ["admin","manager","supervisor"],
      {
        type: "Sales",
        title: "High Value Sale",
        message: `Receipt ${receiptId} total KES ${Number(total).toLocaleString()}.`,
        link: "sales.html"
      },
      branchId
    );
  }
  lowStockAlerts.forEach(alertInfo => {
    notifyUsersByRoles(
      ["admin","manager","storekeeper","supervisor"],
      {
        type: "Inventory",
        title: "Low Stock Alert",
        message: `${alertInfo.product.name} has ${alertInfo.projected} units left (threshold ${alertInfo.threshold}).`,
        link: "inventory.html"
      },
      branchId
    );
  });
  res.json({ saleId, receiptId, total });
});

// ===== Returns & Refunds =====
app.post("/api/returns", authMiddleware, requireRole(["admin","manager","cashier"]), (req, res) => {
  const { receipt_id, items, reason } = req.body || {};
  if(!receipt_id || !items || !Array.isArray(items) || items.length === 0){
    return sendError(res, 400, "Receipt and items required");
  }
  const sale = db.prepare("SELECT * FROM sales WHERE receipt_id = ?").get(receipt_id);
  if(!sale) return sendError(res, 404, "Sale not found");
  const branchId = sale.branch_id || req.user.branch_id;

  const saleItems = db.prepare("SELECT * FROM sale_items WHERE sale_id = ?").all(sale.id);
  let totalRefund = 0;
  const returnItems = [];
  for(const item of items){
    const saleItem = saleItems.find(si => Number(si.product_id) === Number(item.product_id));
    if(!saleItem) return sendError(res, 400, "Product not found in sale");
    const qty = Number(item.qty);
    if(!Number.isFinite(qty) || qty <= 0) return sendError(res, 400, "Invalid return qty");
    if(qty > Number(saleItem.qty)) return sendError(res, 400, "Return qty exceeds sold qty");
    const subtotal = Number(saleItem.price) * qty;
    totalRefund += subtotal;
    returnItems.push({
      product_id: saleItem.product_id,
      product_name: saleItem.product_name,
      qty,
      price: saleItem.price,
      cost_price: saleItem.cost_price || 0,
      subtotal
    });
  }

  const insertReturn = db.prepare(`INSERT INTO returns (sale_id,receipt_id,branch_id,customer_name,cashier_name,reason,total_refund,created_at)
    VALUES (?,?,?,?,?,?,?,?)`);
  const insertReturnItem = db.prepare(`INSERT INTO return_items (return_id,product_id,product_name,qty,price,cost_price,subtotal)
    VALUES (?,?,?,?,?,?,?)`);
  const updateProduct = db.prepare("UPDATE products SET quantity = quantity + ?, updated_at = ? WHERE id = ?");
  const insertMove = db.prepare(`INSERT INTO inventory_movements (product_id,product_name,type,qty,reference,note,user_id,user_name,branch_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);

  const trx = db.transaction(() => {
    const info = insertReturn.run(
      sale.id,
      receipt_id,
      branchId,
      sale.customer_name || "",
      sale.cashier_name || "",
      reason || "Return",
      totalRefund,
      now()
    );
    returnItems.forEach(ri => {
      insertReturnItem.run(info.lastInsertRowid, ri.product_id, ri.product_name, ri.qty, ri.price, ri.cost_price, ri.subtotal);
      updateProduct.run(ri.qty, now(), ri.product_id);
      insertMove.run(ri.product_id, ri.product_name, "IN", ri.qty, receipt_id, "Return", req.user.id, req.user.name, branchId, now());
    });
    return info.lastInsertRowid;
  });

  const returnId = trx();
  logActivity(req.user, "return", "returns", returnId, `Refund ${totalRefund}`, branchId);
  notifyUsersByRoles(
    ["admin","manager","supervisor"],
    {
      type: "Sales",
      title: "Refund Processed",
      message: `Refund ${receipt_id} for KES ${Number(totalRefund).toLocaleString()} was processed.`,
      link: "returns.html"
    },
    branchId
  );
  res.json({ success: true, total_refund: totalRefund });
});

app.get("/api/returns", authMiddleware, requireRole(["admin","manager","cashier","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  const where = branchId ? "WHERE r.branch_id = ?" : "";
  if(branchId) params.push(branchId);
  const rows = db.prepare(`SELECT r.*, b.name as branch_name FROM returns r LEFT JOIN branches b ON r.branch_id = b.id ${where} ORDER BY r.created_at DESC`).all(...params);
  const ids = rows.map(r => r.id);
  let items = [];
  if(ids.length){
    const placeholders = ids.map(() => "?").join(",");
    items = db.prepare(`SELECT * FROM return_items WHERE return_id IN (${placeholders})`).all(...ids);
  }
  const map = {};
  rows.forEach(r => { map[r.id] = { ...r, items: [] }; });
  items.forEach(it => { if(map[it.return_id]) map[it.return_id].items.push(it); });
  res.json(Object.values(map));
});

// ===== Reports =====
app.get("/api/reports/summary", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const { from, to } = req.query;
  const whereParts = [];
  const params = [];
  if(branchId){
    whereParts.push("s.branch_id = ?");
    params.push(branchId);
  }
  const dateFilter = buildDateWhere("s.created_at", from, to);
  whereParts.push(...dateFilter.clauses);
  params.push(...dateFilter.params);
  const where = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

  const salesRow = db.prepare(`
    SELECT COUNT(*) as sales_count,
           COALESCE(SUM(total),0) as revenue,
           COALESCE(AVG(total),0) as avg_order
    FROM sales s
    ${where}
  `).get(...params);

  const itemsRow = db.prepare(`
    SELECT COALESCE(SUM(si.qty),0) as units
    FROM sale_items si
    JOIN sales s ON s.id = si.sale_id
    ${where}
  `).get(...params);

  const profitRow = db.prepare(`
    SELECT COALESCE(SUM((si.price - si.cost_price) * si.qty),0) as profit
    FROM sale_items si
    JOIN sales s ON s.id = si.sale_id
    ${where}
  `).get(...params);

  const invParams = [];
  let invWhere = "";
  if(branchId){
    invWhere = "WHERE branch_id = ?";
    invParams.push(branchId);
  }

  const inventoryRow = db.prepare(`
    SELECT COALESCE(SUM(quantity * price),0) as value
    FROM products
    ${invWhere}
  `).get(...invParams);

  const lowRow = db.prepare(`
    SELECT COUNT(*) as low_stock
    FROM products
    ${invWhere ? invWhere + " AND" : "WHERE"} quantity > 0 AND quantity <= COALESCE(min_stock, reorder_level, 10)
  `).get(...invParams);

  const outRow = db.prepare(`
    SELECT COUNT(*) as out_stock
    FROM products
    ${invWhere ? invWhere + " AND" : "WHERE"} quantity <= 0
  `).get(...invParams);

  res.json({
    revenue: salesRow.revenue,
    sales_count: salesRow.sales_count,
    avg_order: salesRow.avg_order,
    total_units_sold: itemsRow.units,
    inventory_value: inventoryRow.value,
    low_stock_count: lowRow.low_stock,
    out_of_stock_count: outRow.out_stock,
    profit: profitRow.profit,
    margin_percent: salesRow.revenue ? (profitRow.profit / salesRow.revenue) * 100 : 0
  });
});

// ===== Activity Logs =====
app.get("/api/activity-logs", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const { from, to, limit } = req.query;
  const clauses = [];
  const params = [];
  if(branchId){
    clauses.push("al.branch_id = ?");
    params.push(branchId);
  }
  const dateFilter = buildDateWhere("al.created_at", from, to);
  clauses.push(...dateFilter.clauses);
  params.push(...dateFilter.params);
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const lim = Number(limit) || 100;
  const rows = db.prepare(`
    SELECT al.*, b.name as branch_name
    FROM activity_logs al
    LEFT JOIN branches b ON al.branch_id = b.id
    ${where}
    ORDER BY al.created_at DESC
    LIMIT ?
  `).all(...params, lim);
  res.json(rows);
});

app.get("/api/reports/sales-series", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const { from, to } = req.query;
  const whereParts = [];
  const params = [];
  if(branchId){
    whereParts.push("s.branch_id = ?");
    params.push(branchId);
  }
  const dateFilter = buildDateWhere("s.created_at", from, to);
  whereParts.push(...dateFilter.clauses);
  params.push(...dateFilter.params);
  const where = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

  const dateExpr = db.isPostgres ? "LEFT(s.created_at,10)" : "strftime('%Y-%m-%d', s.created_at)";
  const rows = db.prepare(`
    SELECT ${dateExpr} as date, COALESCE(SUM(s.total),0) as total
    FROM sales s
    ${where}
    GROUP BY date
    ORDER BY date ASC
  `).all(...params);

  res.json(rows);
});

app.get("/api/reports/top-products", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const { from, to, limit } = req.query;
  const whereParts = [];
  const params = [];
  if(branchId){
    whereParts.push("s.branch_id = ?");
    params.push(branchId);
  }
  const dateFilter = buildDateWhere("s.created_at", from, to);
  whereParts.push(...dateFilter.clauses);
  params.push(...dateFilter.params);
  const where = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";
  const lim = Number(limit) || 10;

  const rows = db.prepare(`
    SELECT si.product_name,
           COALESCE(SUM(si.qty),0) as qty,
           COALESCE(SUM(si.subtotal),0) as revenue,
           COALESCE(SUM((si.price - si.cost_price) * si.qty),0) as profit
    FROM sale_items si
    JOIN sales s ON s.id = si.sale_id
    ${where}
    GROUP BY si.product_name
    ORDER BY qty DESC
    LIMIT ?
  `).all(...params, lim);

  res.json(rows);
});

app.get("/api/reports/staff-performance", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const { from, to } = req.query;
  const whereParts = [];
  const params = [];
  if(branchId){
    whereParts.push("s.branch_id = ?");
    params.push(branchId);
  }
  const dateFilter = buildDateWhere("s.created_at", from, to);
  whereParts.push(...dateFilter.clauses);
  params.push(...dateFilter.params);
  const where = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

  const rows = db.prepare(`
    SELECT s.cashier_name,
           COUNT(DISTINCT s.id) as sales_count,
           COALESCE(SUM(s.total),0) as revenue,
           COALESCE(SUM((si.price - si.cost_price) * si.qty),0) as profit
    FROM sales s
    LEFT JOIN sale_items si ON si.sale_id = s.id
    ${where}
    GROUP BY s.cashier_id, s.cashier_name
    ORDER BY revenue DESC
  `).all(...params);

  res.json(rows);
});

app.get("/api/reports/low-stock", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const branchId = resolveBranchId(req);
  const params = [];
  let where = "WHERE quantity <= COALESCE(min_stock, reorder_level, 10)";
  if(branchId){
    where += " AND branch_id = ?";
    params.push(branchId);
  }
  const rows = db.prepare(`
    SELECT id,name,category,quantity,reorder_level,min_stock,branch_id
    FROM products
    ${where}
    ORDER BY quantity ASC
  `).all(...params);
  res.json(rows);
});

app.get("/api/reports/export/:type", authMiddleware, requireRole(["admin","manager","supervisor"]), (req, res) => {
  const { type } = req.params;
  const branchId = resolveBranchId(req);
  const { from, to } = req.query;

  if(type === "sales"){
    const whereParts = [];
    const params = [];
    if(branchId){
      whereParts.push("s.branch_id = ?");
      params.push(branchId);
    }
    const dateFilter = buildDateWhere("s.created_at", from, to);
    whereParts.push(...dateFilter.clauses);
    params.push(...dateFilter.params);
    const where = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

    const rows = db.prepare(`
      SELECT s.receipt_id, s.created_at, b.name as branch_name, s.customer_name, s.cashier_name,
             s.payment_mode, s.subtotal, s.discount, s.tax, s.fees_total, s.table_name, s.total,
             (SELECT COALESCE(SUM((si.price - si.cost_price) * si.qty),0) FROM sale_items si WHERE si.sale_id = s.id) as profit
      FROM sales s
      LEFT JOIN branches b ON s.branch_id = b.id
      ${where}
      ORDER BY s.created_at DESC
    `).all(...params);

    return sendCsv(res, "sales.csv", rows, [
      { key: "receipt_id", label: "Receipt ID" },
      { key: "created_at", label: "Date" },
      { key: "branch_name", label: "Branch" },
      { key: "customer_name", label: "Customer" },
      { key: "cashier_name", label: "Cashier" },
      { key: "payment_mode", label: "Payment Mode" },
      { key: "subtotal", label: "Subtotal" },
      { key: "discount", label: "Discount" },
      { key: "tax", label: "Tax" },
      { key: "fees_total", label: "Fees Total" },
      { key: "table_name", label: "Table" },
      { key: "total", label: "Total" },
      { key: "profit", label: "Profit" }
    ]);
  }

  if(type === "products"){
    const params = [];
    let where = "";
    if(branchId){
      where = "WHERE p.branch_id = ?";
      params.push(branchId);
    }
    const rows = db.prepare(`
      SELECT p.name, p.category, b.name as branch_name, s.name as supplier_name,
             p.price, p.quantity, p.reorder_level, p.lead_time, p.barcode
      FROM products p
      LEFT JOIN branches b ON p.branch_id = b.id
      LEFT JOIN suppliers s ON p.supplier_id = s.id
      ${where}
      ORDER BY p.name ASC
    `).all(...params);

    return sendCsv(res, "products.csv", rows, [
      { key: "name", label: "Product" },
      { key: "category", label: "Category" },
      { key: "branch_name", label: "Branch" },
      { key: "supplier_name", label: "Supplier" },
      { key: "price", label: "Price" },
      { key: "quantity", label: "Quantity" },
      { key: "reorder_level", label: "Reorder Level" },
      { key: "lead_time", label: "Lead Time" },
      { key: "barcode", label: "Barcode" }
    ]);
  }

  if(type === "movements"){
    const params = [];
    let where = "";
    if(branchId){
      where = "WHERE m.branch_id = ?";
      params.push(branchId);
    }
    const rows = db.prepare(`
      SELECT m.created_at, b.name as branch_name, m.product_name, m.type, m.qty, m.reference, m.note, m.user_name
      FROM inventory_movements m
      LEFT JOIN branches b ON m.branch_id = b.id
      ${where}
      ORDER BY m.created_at DESC
    `).all(...params);

    return sendCsv(res, "inventory_movements.csv", rows, [
      { key: "created_at", label: "Date" },
      { key: "branch_name", label: "Branch" },
      { key: "product_name", label: "Product" },
      { key: "type", label: "Type" },
      { key: "qty", label: "Qty" },
      { key: "reference", label: "Reference" },
      { key: "note", label: "Note" },
      { key: "user_name", label: "User" }
    ]);
  }

  if(type === "purchase-orders"){
    const params = [];
    let where = "";
    if(branchId){
      where = "WHERE po.branch_id = ?";
      params.push(branchId);
    }
    const rows = db.prepare(`
      SELECT po.po_number, b.name as branch_name, po.supplier_name, po.product_name, po.qty, po.eta_date,
             po.status, po.requested_by_name, po.created_at, po.received_at
      FROM purchase_orders po
      LEFT JOIN branches b ON po.branch_id = b.id
      ${where}
      ORDER BY po.created_at DESC
    `).all(...params);

    return sendCsv(res, "purchase_orders.csv", rows, [
      { key: "po_number", label: "PO Number" },
      { key: "branch_name", label: "Branch" },
      { key: "supplier_name", label: "Supplier" },
      { key: "product_name", label: "Product" },
      { key: "qty", label: "Qty" },
      { key: "eta_date", label: "ETA Date" },
      { key: "status", label: "Status" },
      { key: "requested_by_name", label: "Requested By" },
      { key: "created_at", label: "Created At" },
      { key: "received_at", label: "Received At" }
    ]);
  }

  return sendError(res, 400, "Unsupported export type");
});

// ===== AI Assistant =====
app.post("/api/ai/query", authMiddleware, (req, res) => {
  const rawQuery = (req.body && req.body.query || "").trim();
  const query = rawQuery.toLowerCase();
  if(!query) return sendError(res, 400, "Query required");
  const branchId = resolveBranchId(req) || req.user.branch_id || null;
  const contextPage = req.body && req.body.context_page ? String(req.body.context_page) : null;

  const logConversation = (responseText) => {
    try{
      db.prepare(`INSERT INTO ai_conversations (user_id,user_name,role,message,response,context_page,branch_id,created_at)
        VALUES (?,?,?,?,?,?,?,?)`)
        .run(req.user.id, req.user.name, req.user.role, rawQuery, responseText, contextPage, branchId, now());
    }catch(err){
      // ignore logging errors
    }
  };

  const respond = (text) => {
    logConversation(text);
    return res.json({ response: text });
  };
  const withBranchWhere = branchId ? "WHERE branch_id = ?" : "";
  const branchParam = branchId ? [branchId] : [];

  if(query.includes("today") && query.includes("sales")){
    const start = `${today()}T00:00:00.000Z`;
    const end = `${today()}T23:59:59.999Z`;
    const clauses = ["created_at >= ?", "created_at <= ?"];
    const params = [start, end];
    if(branchId){ clauses.unshift("branch_id = ?"); params.unshift(branchId); }
    const where = `WHERE ${clauses.join(" AND ")}`;
    const row = db.prepare(`SELECT COALESCE(SUM(total),0) as total, COUNT(*) as count FROM sales ${where}`).get(...params);
    return respond(`Today's sales: ${row.count} transactions totaling KES ${Number(row.total || 0).toLocaleString()}.`);
  }

  if(query.includes("low stock") || query.includes("running out")){
    const rows = db.prepare(`SELECT name, quantity FROM products ${withBranchWhere} ORDER BY quantity ASC LIMIT 5`).all(...branchParam);
    if(rows.length === 0) return respond("No low stock items found.");
    const list = rows.map(r => `${r.name} (${r.quantity})`).join(", ");
    return respond(`Low stock items: ${list}.`);
  }

  if(query.includes("reorder") || query.includes("re-order")){
    const rows = db.prepare(`SELECT name, quantity, reorder_level FROM products ${withBranchWhere} WHERE reorder_level IS NOT NULL AND quantity <= reorder_level ORDER BY quantity ASC LIMIT 5`).all(...branchParam);
    if(rows.length === 0) return respond("All items are above reorder level.");
    const list = rows.map(r => `${r.name} (${r.quantity}/${r.reorder_level})`).join(", ");
    return respond(`Items to reorder: ${list}.`);
  }

  if(query.includes("top product") || query.includes("best product") || query.includes("best selling")){
    const row = db.prepare(`
      SELECT si.product_name, COALESCE(SUM(si.qty),0) as qty
      FROM sale_items si
      JOIN sales s ON s.id = si.sale_id
      ${branchId ? "WHERE s.branch_id = ?" : ""}
      GROUP BY si.product_name
      ORDER BY qty DESC
      LIMIT 1
    `).get(...branchParam);
    if(!row || !row.product_name) return respond("No sales data yet to determine top product.");
    return respond(`Top product: ${row.product_name} with ${row.qty} units sold.`);
  }

  if(query.includes("best staff") || query.includes("top staff") || query.includes("staff performance")){
    const row = db.prepare(`
      SELECT cashier_name, COALESCE(SUM(total),0) as total
      FROM sales
      ${branchId ? "WHERE branch_id = ?" : ""}
      GROUP BY cashier_name
      ORDER BY total DESC
      LIMIT 1
    `).get(...branchParam);
    if(!row || !row.cashier_name) return respond("No sales data yet to rank staff performance.");
    return respond(`Best staff: ${row.cashier_name} with total sales KES ${Number(row.total || 0).toLocaleString()}.`);
  }

  if(query.includes("attendance") || query.includes("late") || query.includes("absent") || query.includes("on duty")){
    const params = [];
    let branchWhere = "";
    if(branchId){
      branchWhere = "AND branch_id = ?";
      params.push(branchId);
    }
    const totalStaff = db.prepare(`SELECT COUNT(*) as count FROM users WHERE status = 'active' ${branchWhere}`).get(...params).count;
    const present = db.prepare(`SELECT COUNT(DISTINCT user_id) as count FROM attendance WHERE date = ? ${branchWhere}`).get(today(), ...params).count;
    const late = db.prepare(`SELECT COUNT(*) as count FROM attendance WHERE date = ? AND status LIKE 'late%' ${branchWhere}`).get(today(), ...params).count;
    return respond(`Attendance today: Present ${present}/${totalStaff}, Absent ${Math.max(0, totalStaff - present)}, Late ${late}.`);
  }

  if(query.includes("inventory value") || query.includes("stock value")){
    const row = db.prepare(`SELECT COALESCE(SUM(quantity * price),0) as value FROM products ${withBranchWhere}`).get(...branchParam);
    return respond(`Estimated inventory value: KES ${Number(row.value || 0).toLocaleString()}.`);
  }

  if(query.includes("profit")){
    const row = db.prepare(`
      SELECT COALESCE(SUM((si.price - si.cost_price) * si.qty),0) as profit
      FROM sale_items si
      JOIN sales s ON s.id = si.sale_id
      ${branchId ? "WHERE s.branch_id = ?" : ""}
    `).get(...branchParam);
    return respond(`Estimated profit: KES ${Number(row.profit || 0).toLocaleString()}.`);
  }

  if(query.includes("price")){
    const products = db.prepare(`SELECT id,name,price FROM products ${withBranchWhere}`).all(...branchParam);
    const match = products.find(p => query.includes(p.name.toLowerCase()));
    if(match){
      return respond(`Price for ${match.name} is KES ${Number(match.price).toLocaleString()}.`);
    }
  }

  return respond("I can help with sales, low stock, prices, inventory value, and profit. Try: 'today sales', 'low stock', 'price for sugar'.");
});

// ===== Public Legal Content =====
app.get("/test-legal", (req, res) => {
  console.log('Test legal endpoint called');
  res.send('Legal endpoint works');
});

// ===== Health =====
app.get("/api/health", (req, res) => res.json({ ok: true }));

app.get("/test-legal", (req, res) => {
  console.log('Test legal endpoint called');
  res.send('Legal endpoint works');
});

// ===== Fallback =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Static files
app.use(express.static(__dirname, {
  maxAge: "1h",
  setHeaders: (res, filePath) => {
    if(filePath.endsWith(".html")){
      res.setHeader("Cache-Control", "no-cache");
    }
  }
}));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});

function schedulePostgresBackup(){
  if(!hasValidDatabaseUrl(process.env.DATABASE_URL)) return;
  const intervalMs = Number(process.env.DB_BACKUP_INTERVAL_MS || 60000);
  const scriptPath = path.join(__dirname, "scripts", "pg-backup.js");
  const run = () => {
    try{
      spawn(process.execPath, [scriptPath], { env: process.env, stdio: ["ignore","ignore","inherit"] });
    }catch(err){
      // ignore backup failures
    }
  };
  run();
  setInterval(run, intervalMs);
  process.on("SIGTERM", () => {
    try{
      run();
    }catch(err){}
    setTimeout(() => process.exit(0), 1500);
  });
}

schedulePostgresBackup();
