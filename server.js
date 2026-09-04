import express from "express";
import pg from "pg";
import crypto from "crypto";

const { Pool } = pg;
const app = express();

app.use(express.json({ limit: "100kb" }));
app.use(express.static("public"));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "StarBankey";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "local-admin-session";

function ipOf(req) {
  const x = req.headers["x-forwarded-for"];

  return (
    x
      ? String(x).split(",")[0].trim()
      : req.socket.remoteAddress || ""
  ).replace("::ffff:", "");
}

function deviceHash(req) {
  const raw = [
    req.headers["user-agent"] || "",
    req.headers["accept-language"] || ""
  ].join("|");

  return crypto
    .createHash("sha256")
    .update(raw)
    .digest("hex");
}

function makeKey() {
  return crypto
    .randomBytes(18)
    .toString("base64url")
    .toUpperCase();
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
      key_expires_at TIMESTAMPTZ,
      banned BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS users_ip_idx
      ON users(ip);

    CREATE INDEX IF NOT EXISTS users_device_idx
      ON users(device_hash);

    CREATE INDEX IF NOT EXISTS users_username_idx
      ON users(lower(roblox_username));

    CREATE INDEX IF NOT EXISTS users_roblox_id_idx
      ON users(roblox_user_id);
  `);

  // 旧数据库兼容
  await pool.query(`
    ALTER TABLE users
    ALTER COLUMN key_expires_at DROP NOT NULL
  `).catch(() => {});
}

function requireDb(res) {
  if (!pool) {
    res.status(503).json({
      ok: false,
      error: "DATABASE_URL is not configured."
    });
    return false;
  }

  return true;
}


/* =========================
   Health
========================= */

app.get("/api/health", async (req, res) => {
  if (!pool) {
    return res.json({
      ok: true,
      database: false
    });
  }

  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true
    });
  } catch (e) {
    console.error(e);

    res.status(503).json({
      ok: false,
      database: false
    });
  }
});


/* =========================
   创建 Key
========================= */

app.post("/api/key", async (req, res) => {
  if (!requireDb(res)) return;

  const username = String(
    req.body.username || ""
  ).trim().slice(0, 50);

  const robloxUserId = String(
    req.body.robloxUserId || ""
  ).trim().slice(0, 30);

  if (!username) {
    return res.status(400).json({
      ok: false,
      error: "请输入 Roblox 用户名。"
    });
  }

  const ip = ipOf(req);
  const device = deviceHash(req);

  try {

    /* 封禁检查 */

    const blocked = await pool.query(
      `
      SELECT 1
      FROM users
      WHERE banned = true
      AND (
        ip = $1
        OR device_hash = $2
        OR (
          roblox_user_id IS NOT NULL
          AND roblox_user_id = $3
        )
      )
      LIMIT 1
      `,
      [ip, device, robloxUserId]
    );

    if (blocked.rowCount) {
      return res.status(403).json({
        ok: false,
        error: "此账号或设备已被封禁。"
      });
    }


    /* 查找当前 Roblox 账户 */

    const existing = await pool.query(
      `
      SELECT id, key
      FROM users
      WHERE
        lower(roblox_username) = lower($1)
        AND roblox_user_id IS NOT DISTINCT FROM $2
      LIMIT 1
      `,
      [username, robloxUserId]
    );


    /* 已经存在 */

    if (existing.rowCount) {

      await pool.query(
        `
        UPDATE users
        SET
          ip = $1,
          device_hash = $2,
          key_expires_at = NULL,
          last_seen_at = NOW()
        WHERE id = $3
        `,
        [
          ip,
          device,
          existing.rows[0].id
        ]
      );

      return res.json({
        ok: true,
        key: existing.rows[0].key,
        permanent: true,
        expiresAt: null
      });
    }


    /* 新建永久 Key */

    const key = makeKey();

    await pool.query(
      `
      INSERT INTO users (
        roblox_username,
        roblox_user_id,
        ip,
        device_hash,
        key,
        key_expires_at
      )
      VALUES ($1, $2, $3, $4, $5, NULL)
      `,
      [
        username,
        robloxUserId || null,
        ip,
        device,
        key
      ]
    );

    res.json({
      ok: true,
      key,
      permanent: true,
      expiresAt: null
    });

  } catch (e) {

    console.error("KEY ERROR:", e);

    res.status(500).json({
      ok: false,
      error: "服务器错误。"
    });
  }
});


/* =========================
   Roblox /api/verify
========================= */

app.post("/api/verify", async (req, res) => {
  if (!requireDb(res)) return;

  const username = String(
    req.body.username || ""
  ).trim();

  const robloxUserId = String(
    req.body.robloxUserId || ""
  ).trim();

  const key = String(
    req.body.key || ""
  ).trim()
  .toUpperCase();

  if (!key) {
    return res.status(400).json({
      ok: false,
      error: "缺少密钥。"
    });
  }

  try {

    /*
      优先通过 Key + Roblox UserId
      也兼容用户名验证
    */

    const r = await pool.query(
      `
      SELECT *
      FROM users
      WHERE key = $1
      AND (
        (
          $2 <> ''
          AND roblox_user_id = $2
        )
        OR
        (
          $3 <> ''
          AND lower(roblox_username) = lower($3)
        )
      )
      LIMIT 1
      `,
      [
        key,
        robloxUserId,
        username
      ]
    );

    if (!r.rowCount) {
      return res.status(401).json({
        ok: false,
        error: "密钥错误或未绑定此 Roblox 账户。"
      });
    }

    const u = r.rows[0];


    /* 封禁 */

    if (u.banned) {
      return res.status(403).json({
        ok: false,
        error: "账号已被封禁。"
      });
    }


    /* 永久 Key 不检查过期 */

    if (
      u.key_expires_at &&
      new Date(u.key_expires_at).getTime() < Date.now()
    ) {
      return res.status(401).json({
        ok: false,
        error: "密钥已过期。"
      });
    }


    /* 更新最后验证时间 */

    await pool.query(
      `
      UPDATE users
      SET last_seen_at = NOW()
      WHERE id = $1
      `,
      [u.id]
    );


    res.json({
      ok: true,
      username: u.roblox_username,
      robloxUserId: u.roblox_user_id,
      permanent: u.key_expires_at === null,
      expiresAt: u.key_expires_at
        ? new Date(u.key_expires_at).toISOString()
        : null
    });

  } catch (e) {

    console.error("VERIFY ERROR:", e);

    res.status(500).json({
      ok: false,
      error: "服务器错误。"
    });
  }
});


/* =========================
   Admin Login
========================= */

app.post("/api/admin/login", (req, res) => {

  if (
    String(req.body.password || "") ===
    ADMIN_PASSWORD
  ) {
    return res.json({
      ok: true,
      token: ADMIN_TOKEN
    });
  }

  res.status(401).json({
    ok: false,
    error: "密码错误。"
  });
});


/* =========================
   Admin Middleware
========================= */

function admin(req, res, next) {

  if (
    req.headers.authorization ===
    `Bearer ${ADMIN_TOKEN}`
  ) {
    return next();
  }

  res.status(401).json({
    ok: false,
    error: "未授权"
  });
}


/* =========================
   Admin Users
========================= */

app.get(
  "/api/admin/users",
  admin,
  async (req, res) => {

    if (!requireDb(res)) return;

    try {

      const r = await pool.query(`
        SELECT
          id,
          roblox_username,
          roblox_user_id,
          ip,
          device_hash,
          key,
          key_expires_at,
          banned,
          created_at,
          last_seen_at
        FROM users
        ORDER BY id DESC
        LIMIT 500
      `);

      res.json({
        ok: true,
        users: r.rows
      });

    } catch (e) {

      console.error(e);

      res.status(500).json({
        ok: false,
        error: "服务器错误。"
      });
    }
  }
);


/* =========================
   Ban
========================= */

app.post(
  "/api/admin/ban",
  admin,
  async (req, res) => {

    if (!requireDb(res)) return;

    const id = Number(req.body.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        ok: false,
        error: "无效用户 ID"
      });
    }

    await pool.query(
      "UPDATE users SET banned = true WHERE id = $1",
      [id]
    );

    res.json({
      ok: true
    });
  }
);


/* =========================
   Unban
========================= */

app.post(
  "/api/admin/unban",
  admin,
  async (req, res) => {

    if (!requireDb(res)) return;

    const id = Number(req.body.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        ok: false,
        error: "无效用户 ID"
      });
    }

    await pool.query(
      "UPDATE users SET banned = false WHERE id = $1",
      [id]
    );

    res.json({
      ok: true
    });
  }
);


/* =========================
   Start
========================= */

const port = process.env.PORT || 3000;

init()
  .then(() => {

    app.listen(port, () => {
      console.log(
        `StarKey listening on ${port}`
      );
    });

  })
  .catch((err) => {

    console.error(
      "DATABASE INIT ERROR:",
      err
    );

    process.exit(1);
  });
