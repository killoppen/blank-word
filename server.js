const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3001;
const TOKEN_EXPIRY = '30d';

// ---------- 密钥 & 数据库 ----------
const fs = require('fs');
const dataDir = process.env.DATA_DIR || __dirname;
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const secretFile = path.join(dataDir, '.jwt_secret');
let JWT_SECRET;
if (process.env.JWT_SECRET) {
  JWT_SECRET = process.env.JWT_SECRET;
} else if (fs.existsSync(secretFile)) {
  JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
} else {
  JWT_SECRET = require('crypto').randomBytes(32).toString('hex');
  fs.writeFileSync(secretFile, JWT_SECRET);
}

const db = new Database(path.join(dataDir, 'data.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS notebooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ---------- 中间件 ----------
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// 鉴权中间件
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: '请先登录' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = decoded.userId;
    req.username = decoded.username;
    next();
  } catch (e) {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

// ---------- API ----------

// 注册
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: '用户名需 2-20 个字符' });
  if (password.length < 4) return res.status(400).json({ error: '密码至少 4 位' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: '用户名已存在' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hash);
  const token = jwt.sign({ userId: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  res.json({ token, username });
});

// 登录
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });

  const user = db.prepare('SELECT id, password FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: '用户名或密码错误' });
  }

  const token = jwt.sign({ userId: user.id, username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
  res.json({ token, username });
});

// 获取数据
app.get('/api/data', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT data FROM notebooks WHERE user_id = ?').get(req.userId);
  const notebooks = row ? JSON.parse(row.data) : {};
  res.json({ data: notebooks });
});

// 保存数据
app.post('/api/data', authMiddleware, (req, res) => {
  const { notebooks, activeNotebookId } = req.body;
  const data = JSON.stringify({ notebooks: notebooks || {}, activeNotebookId: activeNotebookId || null });

  const existing = db.prepare('SELECT id FROM notebooks WHERE user_id = ?').get(req.userId);
  if (existing) {
    db.prepare('UPDATE notebooks SET data = ?, updated_at = datetime(\'now\') WHERE user_id = ?').run(data, req.userId);
  } else {
    db.prepare('INSERT INTO notebooks (user_id, data) VALUES (?, ?)').run(req.userId, data);
  }

  res.json({ ok: true });
});

// 主页
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '空白格.html'));
});

app.listen(PORT, () => {
  console.log(`🌻 空白格服务已启动: http://localhost:${PORT}`);
});
