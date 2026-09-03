import express from "express";
import pg from "pg";
import crypto from "crypto";

const { Pool } = pg;
const app = express();
app.use(express.json({limit:"100kb"}));
app.use(express.static("public"));

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "StarBankey";
const KEY_MINUTES = Number(process.env.KEY_MINUTES || 15);

function ipOf(req) {
  const x = req.headers["x-forwarded-for"];
  return (x ? String(x).split(",")[0].trim() : req.socket.remoteAddress || "").replace("::ffff:","");
}
function deviceHash(req) {
  const raw = [
    req.headers["user-agent"] || "",
    req.headers["accept-language"] || ""
  ].join("|");
  return crypto.createHash("sha256").update(raw).digest("hex");
}
function makeKey() {
  return crypto.randomBytes(18).toString("base64url").toUpperCase();
}
async function init() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      roblox_username TEXT NOT NULL,
      roblox_user_id TEXT,
      ip TEXT NOT NULL,
      device_hash TEXT NOT NULL,
      key TEXT NOT NULL UNIQUE,
      key_expires_at TIMESTAMPTZ NOT NULL,
      banned BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS users_ip_idx ON users(ip);
    CREATE INDEX IF NOT EXISTS users_device_idx ON users(device_hash);
    CREATE INDEX IF NOT EXISTS users_username_idx ON users(lower(roblox_username));
  `);
}
function requireDb(res) {
  if (!pool) {
    res.status(503).json({ok:false,error:"DATABASE_URL is not configured."});
    return false;
  }
  return true;
}

app.get("/api/health", async (req,res) => {
  if (!pool) return res.json({ok:true,database:false});
  try { await pool.query("SELECT 1"); res.json({ok:true,database:true}); }
  catch { res.status(503).json({ok:false,database:false}); }
});

app.post("/api/key", async (req,res) => {
  if (!requireDb(res)) return;
  const username = String(req.body.username || "").trim().slice(0,50);
  const robloxUserId = String(req.body.robloxUserId || "").trim().slice(0,30);
  if (!username) return res.status(400).json({ok:false,error:"请输入 Roblox 用户名。"});

  const ip = ipOf(req);
  const device = deviceHash(req);

  try {
    const blocked = await pool.query(
      `SELECT 1 FROM users WHERE banned=true AND (ip=$1 OR device_hash=$2 OR (roblox_user_id IS NOT NULL AND roblox_user_id=$3)) LIMIT 1`,
      [ip,device,robloxUserId]
    );
    if (blocked.rowCount) return res.status(403).json({ok:false,error:"此账号或设备已被封禁。"});

    const sameDevice = await pool.query(
      `SELECT roblox_username FROM users WHERE device_hash=$1 AND banned=false AND roblox_user_id IS DISTINCT FROM $2 LIMIT 1`,
      [device,robloxUserId]
    );
    if (sameDevice.rowCount) return res.status(409).json({ok:false,error:"此设备已经绑定其他 Roblox 账号。"});

    const key = makeKey();
    const expires = new Date(Date.now() + KEY_MINUTES*60*1000);

    const existing = await pool.query(
      `SELECT id FROM users WHERE lower(roblox_username)=lower($1) AND roblox_user_id IS NOT DISTINCT FROM $2 LIMIT 1`,
      [username, robloxUserId]
    );
    if (existing.rowCount) {
      await pool.query(
        `UPDATE users SET key=$1,key_expires_at=$2,ip=$3,device_hash=$4,last_seen_at=NOW() WHERE id=$5`,
        [key,expires,ip,device,existing.rows[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO users(roblox_username,roblox_user_id,ip,device_hash,key,key_expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
        [username,robloxUserId || null,ip,device,key,expires]
      );
    }
    res.json({ok:true,key,expiresAt:expires.toISOString()});
  } catch(e) {
    console.error(e);
    res.status(500).json({ok:false,error:"服务器错误。"});
  }
});

app.post("/api/verify", async (req,res) => {
  if (!requireDb(res)) return;
  const username = String(req.body.username || "").trim();
  const key = String(req.body.key || "").trim().toUpperCase();
  if (!username || !key) return res.status(400).json({ok:false,error:"缺少用户名或密钥。"});

  try {
    const r = await pool.query(
      `SELECT * FROM users WHERE lower(roblox_username)=lower($1) AND key=$2 LIMIT 1`,
      [username,key]
    );
    if (!r.rowCount) return res.status(401).json({ok:false,error:"密钥错误。"});
    const u = r.rows[0];
    if (u.banned) return res.status(403).json({ok:false,error:"账号已被封禁。"});
    if (new Date(u.key_expires_at).getTime() < Date.now())
      return res.status(401).json({ok:false,error:"密钥已过期。"});
    await pool.query("UPDATE users SET last_seen_at=NOW() WHERE id=$1",[u.id]);
    res.json({ok:true,username:u.roblox_username});
  } catch {
    res.status(500).json({ok:false,error:"服务器错误。"});
  }
});

app.post("/api/admin/login", (req,res) => {
  if (String(req.body.password || "") === ADMIN_PASSWORD)
    return res.json({ok:true,token:process.env.ADMIN_TOKEN || "local-admin-session"});
  res.status(401).json({ok:false,error:"密码错误。"});
});

function admin(req,res,next) {
  const expected = process.env.ADMIN_TOKEN || "local-admin-session";
  if (req.headers.authorization === `Bearer ${expected}`) return next();
  res.status(401).json({ok:false,error:"未授权"});
}
app.get("/api/admin/users", admin, async (req,res) => {
  if (!requireDb(res)) return;
  const r = await pool.query(`SELECT id,roblox_username,roblox_user_id,ip,device_hash,key,key_expires_at,banned,created_at,last_seen_at FROM users ORDER BY id DESC LIMIT 500`);
  res.json({ok:true,users:r.rows});
});
app.post("/api/admin/ban", admin, async (req,res) => {
  if (!requireDb(res)) return;
  const id = Number(req.body.id);
  await pool.query("UPDATE users SET banned=true WHERE id=$1",[id]);
  res.json({ok:true});
});
app.post("/api/admin/unban", admin, async (req,res) => {
  if (!requireDb(res)) return;
  const id = Number(req.body.id);
  await pool.query("UPDATE users SET banned=false WHERE id=$1",[id]);
  res.json({ok:true});
});

const port = process.env.PORT || 3000;
init().then(()=>app.listen(port,()=>console.log(`StarKey listening on ${port}`)));
