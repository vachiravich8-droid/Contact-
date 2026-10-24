const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const SECRET = process.env.SECRET || 'change-this-secret-in-production';

const DEFAULT_CONFIG = {
  tagline: 'พร้อมตอบทุกข้อสงสัย',
  subhead: 'เลือกช่องทางที่คุณสะดวกที่สุด ทีมงานพร้อมตอบกลับภายใน 24 ชั่วโมง',
  robloxName: 'ชื่อแมพของคุณ',
  robloxUrl: 'https://www.roblox.com/games/your-game-id',
  robloxDesc: 'เล่นแมพของเราได้เลยบน Roblox',
  fbUrl: 'https://www.facebook.com/your-facebook', fbHandle: 'facebook.com/your-facebook',
  igUrl: 'https://www.instagram.com/your_ig', igHandle: '@your_ig',
  lineUrl: 'https://line.me/ti/p/your-line-id', lineHandle: 'ID: @your_line_id',
  discordUrl: 'https://discord.gg/your-invite', discordHandle: 'discord.gg/your-invite',
  email: 'hello@yourbrand.com',
  hours: 'เวลาทำการ: จันทร์ – เสาร์ 09:00 – 18:00 น.'
};

function loadData() {
  if (fs.existsSync(DATA_FILE)) {
    try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { /* fall through */ }
  }
  const initial = {
    admin: { user: 'admin', passHash: bcrypt.hashSync('admin123', 10) },
    config: DEFAULT_CONFIG
  };
  fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
  return initial;
}
let data = loadData();
function saveData() { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 2 * 60 * 60 * 1000 } // 2 ชั่วโมง
}));
app.use(express.static(path.join(__dirname, 'public')));

// === Public API ===
app.get('/api/config', (req, res) => res.json(data.config));
app.get('/api/me', (req, res) => res.json({ loggedIn: !!req.session.admin, user: req.session.admin || null }));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.json({ ok: false, msg: 'กรอกชื่อผู้ใช้และรหัสผ่าน' });
  const ok = username === data.admin.user && bcrypt.compareSync(String(password), data.admin.passHash);
  if (!ok) return res.json({ ok: false, msg: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
  req.session.admin = username;
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// === Auth guard ===
function requireAuth(req, res, next) {
  if (req.session.admin) return next();
  res.status(401).json({ ok: false, msg: 'ต้องเข้าสู่ระบบก่อน' });
}

app.post('/api/config', requireAuth, (req, res) => {
  const b = req.body || {};
  const cleaned = {};
  Object.keys(DEFAULT_CONFIG).forEach(k => {
    cleaned[k] = (b[k] !== undefined && b[k] !== null && String(b[k]).trim() !== '') ? String(b[k]).trim() : DEFAULT_CONFIG[k];
  });
  data.config = cleaned;
  saveData();
  res.json({ ok: true, config: data.config });
});

app.post('/api/password', requireAuth, (req, res) => {
  const { oldPass, newPass } = req.body || {};
  if (!bcrypt.compareSync(String(oldPass || ''), data.admin.passHash))
    return res.json({ ok: false, msg: 'รหัสผ่านเก่าไม่ถูกต้อง' });
  if (!newPass || String(newPass).length < 6)
    return res.json({ ok: false, msg: 'รหัสผ่านใหม่ต้องอย่างน้อย 6 ตัวอักษร' });
  data.admin.passHash = bcrypt.hashSync(String(newPass), 10);
  saveData();
  res.json({ ok: true });
});

// Admin dashboard page
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.listen(PORT, () => {
  console.log('✅ เซิร์ฟเวอร์เปิดที่ http://localhost:' + PORT);
  console.log('🔐 หน้าแอดมิน: http://localhost:' + PORT + '/admin  (admin / admin123 — อย่าลืมเปลี่ยนรหัสผ่าน!)');
});
