const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ===== MySQL Pool =====
const pool = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "sheet_metal_report",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: "utf8mb4",
});

// ===== Middlewares =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // 如果你之後上 HTTPS 再加 secure: true
      // 建議上線加 maxAge，避免永遠登入
      // maxAge: 1000 * 60 * 60 * 8
    },
  })
);

// ===== Auth Guards =====
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login.html");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect("/login.html");
  if (req.session.user.role !== "admin") return res.status(403).json({ ok: false, msg: "沒有權限" });
  next();
}
function requireAdminPage(req, res, next) {
  if (!req.session.user) return res.redirect("/login.html");
  if (req.session.user.role !== "admin") return res.redirect("/index.html");
  next();
}

// ===== 先保護頁面（重要：要放在 static 之前，避免被直接讀到檔案）=====
app.get(["/index.html", "/repo.html"], requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", req.path));
});
app.get("/admin_users.html", requireAdminPage, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin_users.html"));
});

// ===== 靜態檔案（放在 guards 後面）=====
app.use(express.static(path.join(__dirname, "public")));

// ===== API: current user =====
app.get("/api/me", requireLogin, (req, res) => {
  res.json({ ok: true, user: req.session.user });
});

// ===== LOGIN =====
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ ok: false, msg: "缺少帳號或密碼" });
    }

    // ✅ 加上 is_active 檢查：停用就不能登入
    const [rows] = await pool.query(
      "SELECT id, username, password_hash, station, operator, role, is_active FROM users WHERE username=? LIMIT 1",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ ok: false, msg: "帳號或密碼錯誤" });
    }

    const u = rows[0];

    if (Number(u.is_active) !== 1) {
      return res.status(403).json({ ok: false, msg: "此帳號已停用" });
    }

    const passOk = await bcrypt.compare(password, u.password_hash);
    if (!passOk) {
      return res.status(401).json({ ok: false, msg: "帳號或密碼錯誤" });
    }

    req.session.user = {
      id: u.id,
      username: u.username,
      station: u.station,
      operator: u.operator,
      role: u.role,
    };

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "登入失敗(伺服器錯誤)" });
  }
});

// ===== LOGOUT =====
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ===== Orders: 掃條碼查工單 =====
app.get("/api/order/:orderNo", requireLogin, async (req, res) => {
  try {
    const orderNo = req.params.orderNo;
    const [rows] = await pool.query(
      "SELECT order_no, item_name, item_no, order_qty FROM orders WHERE order_no=? LIMIT 1",
      [orderNo]
    );
    if (rows.length === 0) return res.status(404).json({ ok: false, msg: "查無此工單" });
    res.json({ ok: true, order: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "查詢失敗" });
  }
});

// ===== Reports: 新增報工 =====
app.post("/api/report", requireLogin, async (req, res) => {
  try {
    const user = req.session.user;

    const orderNo = (req.body.orderNo || req.body.order_no || "").trim();
    const itemName = (req.body.itemName || req.body.item_name || "").trim();
    const itemNo = (req.body.itemNo || req.body.item_no || "").trim();
    const goodQty = Number(req.body.goodNumber ?? req.body.good_qty ?? 0);
    const badQty = Number(req.body.badNumber ?? req.body.bad_qty ?? 0);

    if (!orderNo || !itemName || !itemNo) {
      return res.status(400).json({ ok: false, msg: "缺少工單資料(請先掃條碼)" });
    }

    if (!Number.isFinite(goodQty) || !Number.isFinite(badQty) || goodQty < 0 || badQty < 0) {
      return res.status(400).json({ ok: false, msg: "數量格式錯誤" });
    }

    await pool.query(
      `INSERT INTO reports(station, order_no, item_name, item_no, operator, good_qty, bad_qty)
       VALUES(?,?,?,?,?,?,?)`,
      [user.station, orderNo, itemName, itemNo, user.operator, goodQty, badQty]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "寫入報工失敗" });
  }
});

// ===== Reports: 查詢（repo.html 用）=====
// ✅ 權限規則：
// - admin：可看全部 + 可用 query 篩選
// - 非 admin：只能看「自己 + 今天」
app.get("/api/reports", requireLogin, async (req, res) => {
  try {
    const user = req.session.user;

    // admin：支援 query
    if (user.role === "admin") {
      const { from, to, station, operator, order_no, item_name } = req.query;

      let sql = `
        SELECT id, station, order_no, item_name, item_no, operator, good_qty, bad_qty, report_time
        FROM reports
        WHERE 1=1
      `;
      const params = [];

      // 日期篩選：from/to
      if (from) {
        sql += " AND DATE(report_time) >= ?";
        params.push(from);
      }
      if (to) {
        sql += " AND DATE(report_time) <= ?";
        params.push(to);
      }

      if (station) {
        sql += " AND station LIKE ?";
        params.push(`%${station}%`);
      }
      if (operator) {
        sql += " AND operator LIKE ?";
        params.push(`%${operator}%`);
      }
      if (order_no) {
        sql += " AND order_no LIKE ?";
        params.push(`%${order_no}%`);
      }
      if (item_name) {
        sql += " AND item_name LIKE ?";
        params.push(`%${item_name}%`);
      }

      sql += " ORDER BY id DESC LIMIT 5000";

      const [rows] = await pool.query(sql, params);
      return res.json({ ok: true, rows });
    }

    // 非 admin：只能看自己今天（用 operator + 今天）
    const [rows] = await pool.query(
      `SELECT id, station, order_no, item_name, item_no, operator, good_qty, bad_qty, report_time
       FROM reports
       WHERE operator = ?
         AND DATE(report_time) = CURDATE()
       ORDER BY id DESC
       LIMIT 2000`,
      [user.operator]
    );

    res.json({ ok: true, rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "查詢失敗" });
  }
});

// ===== （建議）清空報工：你說怕現場清掉資料，所以我直接封鎖 =====
app.post("/api/reports/clear", requireLogin, async (req, res) => {
  return res.status(403).json({ ok: false, msg: "已停用此功能" });
});

// ================================
// ✅ A) Admin Users 管理 API
// ================================

// list users
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, username, station, operator, role, is_active
       FROM users
       ORDER BY id DESC
       LIMIT 5000`
    );
    res.json({ ok: true, rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "查詢使用者失敗" });
  }
});

// create user
app.post("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const { username, password, station, operator, role } = req.body;

    if (!username || !password) return res.status(400).json({ ok: false, msg: "缺少 username 或 password" });

    const r = (role || "viewer").trim();
    if (!["admin", "editor", "viewer"].includes(r)) {
      return res.status(400).json({ ok: false, msg: "role 只能是 admin/editor/viewer" });
    }

    // 避免重複帳號
    const [exists] = await pool.query("SELECT id FROM users WHERE username=? LIMIT 1", [username.trim()]);
    if (exists.length) return res.status(409).json({ ok: false, msg: "帳號已存在" });

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO users(username, password_hash, station, operator, role, is_active)
       VALUES(?,?,?,?,?,1)`,
      [username.trim(), hash, (station || "").trim(), (operator || "").trim(), r]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "新增使用者失敗" });
  }
});

// update user (role/station/operator/is_active)
app.put("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, msg: "id 不正確" });

    const { station, operator, role, is_active } = req.body;

    // 防呆 role
    if (role && !["admin", "editor", "viewer"].includes(String(role))) {
      return res.status(400).json({ ok: false, msg: "role 只能是 admin/editor/viewer" });
    }

    // 不允許把自己停用（避免鎖死）
    if (req.session.user.id === id && is_active !== undefined && Number(is_active) !== 1) {
      return res.status(400).json({ ok: false, msg: "不能停用自己" });
    }

    const fields = [];
    const params = [];

    if (station !== undefined) { fields.push("station=?"); params.push(String(station).trim()); }
    if (operator !== undefined) { fields.push("operator=?"); params.push(String(operator).trim()); }
    if (role !== undefined) { fields.push("role=?"); params.push(String(role).trim()); }
    if (is_active !== undefined) { fields.push("is_active=?"); params.push(Number(is_active) ? 1 : 0); }

    if (!fields.length) return res.status(400).json({ ok: false, msg: "沒有要更新的欄位" });

    params.push(id);
    await pool.query(`UPDATE users SET ${fields.join(", ")} WHERE id=?`, params);

    // 若修改的是自己，更新 session（站別/作業員/角色）
    if (req.session.user.id === id) {
      if (station !== undefined) req.session.user.station = String(station).trim();
      if (operator !== undefined) req.session.user.operator = String(operator).trim();
      if (role !== undefined) req.session.user.role = String(role).trim();
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "更新使用者失敗" });
  }
});

// reset password
app.post("/api/admin/users/:id/reset_password", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { password } = req.body;
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, msg: "id 不正確" });
    if (!password) return res.status(400).json({ ok: false, msg: "缺少新密碼" });

    const hash = await bcrypt.hash(String(password), 10);
    await pool.query("UPDATE users SET password_hash=? WHERE id=?", [hash, id]);

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, msg: "重設密碼失敗" });
  }
});

// ===== Root 導向 =====
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/index.html");
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log(`✅ Server running: http://localhost:${PORT}`);
});