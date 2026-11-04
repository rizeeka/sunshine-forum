require("dotenv").config();
const path = require("path");
const fs = require("fs");
const http = require("http");
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT || 3000);
const dataDir = path.resolve(process.env.DATABASE_DIR || "./data");
fs.mkdirSync(dataDir, { recursive: true });

if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET must be set in production.");
}
const db = new Database(path.join(dataDir, "sunshine.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  bio TEXT NOT NULL DEFAULT '',
  avatar TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category TEXT NOT NULL DEFAULT 'Идеи',
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reactions (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  reaction TEXT NOT NULL DEFAULT 'like',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  topic TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Новая',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS chat_mutes (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  moderator_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  muted_until TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL, target_type TEXT NOT NULL DEFAULT '', target_id INTEGER, details TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_settings (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  notify_likes INTEGER NOT NULL DEFAULT 1, notify_comments INTEGER NOT NULL DEFAULT 1,
  notify_reports INTEGER NOT NULL DEFAULT 1, private_profile INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS report_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS post_polls (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL UNIQUE REFERENCES posts(id) ON DELETE CASCADE, question TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS poll_options (id INTEGER PRIMARY KEY AUTOINCREMENT, poll_id INTEGER NOT NULL REFERENCES post_polls(id) ON DELETE CASCADE, label TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS poll_votes (poll_id INTEGER NOT NULL REFERENCES post_polls(id) ON DELETE CASCADE, option_id INTEGER NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(poll_id,user_id));
CREATE TABLE IF NOT EXISTS idea_votes (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  value INTEGER NOT NULL CHECK(value IN (-1,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id,post_id)
);
CREATE TABLE IF NOT EXISTS chat_reactions (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  reaction TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id,message_id)
);
CREATE TABLE IF NOT EXISTS chat_attachments (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, attachment_id INTEGER NOT NULL REFERENCES attachments(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS chat_polls (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE, question TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chat_poll_options (id INTEGER PRIMARY KEY AUTOINCREMENT, poll_id INTEGER NOT NULL REFERENCES chat_polls(id) ON DELETE CASCADE, label TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chat_poll_votes (poll_id INTEGER NOT NULL REFERENCES chat_polls(id) ON DELETE CASCADE, option_id INTEGER NOT NULL REFERENCES chat_poll_options(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(poll_id,user_id));
CREATE TABLE IF NOT EXISTS attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE, mime TEXT NOT NULL, size INTEGER NOT NULL,
  post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, report_id INTEGER REFERENCES reports(id) ON DELETE CASCADE, comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

try { db.exec("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE attachments ADD COLUMN comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE"); } catch {}
try { db.exec("ALTER TABLE reactions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE notifications ADD COLUMN target_type TEXT NOT NULL DEFAULT ''"); } catch {}
try { db.exec("ALTER TABLE notifications ADD COLUMN target_id INTEGER"); } catch {}
const onlineSockets = new Map();
const audit = (actor, action, type = '', target = null, details = '') => db.prepare(
  "INSERT INTO audit_logs(actor_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)"
).run(actor || null, action, type, target, clean(details, 500));
const uploadDir = path.join(dataDir, "uploads"); fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ storage: multer.diskStorage({ destination: uploadDir, filename: (req,file,cb) => { const ext=({"image/jpeg":".jpg","image/png":".png","image/webp":".webp","image/gif":".gif","video/mp4":".mp4","video/webm":".webm","application/pdf":".pdf","text/plain":".txt","application/vnd.openxmlformats-officedocument.wordprocessingml.document":".docx"})[file.mimetype] || ".bin"; cb(null, require("crypto").randomBytes(18).toString("hex") + ext); } }), limits: { fileSize: 25 * 1024 * 1024, files: 5 }, fileFilter: (req,file,cb) => {
  const allowed = /^(image\/(png|jpeg|webp|gif)|video\/(mp4|webm)|application\/pdf|text\/plain|application\/vnd\.openxmlformats-officedocument\.wordprocessingml\.document)$/;
  cb(allowed.test(file.mimetype) ? null : new Error("Этот тип файла не поддерживается."), allowed.test(file.mimetype));
} });
const telegram = async (text) => {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) return;
  try { await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({chat_id:process.env.TELEGRAM_CHAT_ID,text,parse_mode:"HTML"}) }); }
  catch (e) { console.error("Telegram notification failed:", e.message); }
};
const SQLiteStore = SQLiteStoreFactory(session);
const sessionMiddleware = session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir, concurrentDB: true }),
  secret: process.env.SESSION_SECRET || "local-development-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "40kb" }));
app.use(express.urlencoded({ extended: false, limit: "40kb" }));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 25, standardHeaders: true, legacyHeaders: false });
const postLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const clean = (v, max) => String(v || "").trim().slice(0, max);
const publicUser = u => ({ id: u.id, username: u.username, bio: u.bio, avatar: u.avatar || "", role: u.role, created_at: u.created_at });
const getUser = id => db.prepare("SELECT * FROM users WHERE id=?").get(id);
const requireAuth = (req, res, next) => {
  const user = req.session.userId && getUser(req.session.userId || 0);
  if (!user || user.status !== "active") return res.status(401).json({ error: "Сначала войдите в аккаунт." });
  req.user = user;
  next();
};
const requireAdmin = (req, res, next) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Недостаточно прав." });
  next();
};
const requireStaff = (req,res,next) => { if (!["admin","moderator"].includes(req.user.role)) return res.status(403).json({error:"Недостаточно прав."}); next(); };
const notify = (userId, text, targetType = "", targetId = null) => {
  db.prepare("INSERT OR IGNORE INTO user_settings(user_id) VALUES(?)").run(userId);
  db.prepare("INSERT INTO notifications(user_id,text,target_type,target_id) VALUES(?,?,?,?)").run(userId, text, targetType, targetId);
  const unread=db.prepare("SELECT COUNT(*) n FROM notifications WHERE user_id=? AND read=0").get(userId).n;
  io.to("user:" + userId).emit("notification", { text, unread, targetType, targetId });
};
const notifyMentions = (body, actor, context, targetType = "", targetId = null) => {
  const tags=[...String(body||"").matchAll(/@([\p{L}\p{N}_-]{3,24})/gu)].map(x=>x[1]);
  for(const tag of new Set(tags)){const target=db.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE AND status='active'").get(tag);if(target && target.id!==actor.id)notify(target.id,`Вас упомянул(а) ${actor.username} ${context}.`,targetType,targetId);}
};

app.get("/api/me", (req, res) => {
  const u = req.session.userId && getUser(req.session.userId || 0);
  const user = u && u.status === "active" ? publicUser(u) : null;
  res.json({ user, unread: user ? db.prepare("SELECT COUNT(*) n FROM notifications WHERE user_id=? AND read=0").get(user.id).n : 0 });
});

app.post("/api/register", authLimiter, async (req, res) => {
  const username = clean(req.body.username, 24);
  const email = clean(req.body.email, 120).toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) return res.status(400).json({ error: "Никнейм: 3–24 символа, буквы, цифры, _ или -." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Проверьте адрес электронной почты." });
  if (password.length < 8 || password.length > 100) return res.status(400).json({ error: "Пароль должен содержать от 8 до 100 символов." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)").run(username, email, hash);
    req.session.userId = result.lastInsertRowid;
    db.prepare("INSERT OR IGNORE INTO user_settings(user_id) VALUES(?)").run(result.lastInsertRowid);
    audit(result.lastInsertRowid, "user.register", "user", result.lastInsertRowid);
    res.json({ user: publicUser(getUser(result.lastInsertRowid)) });
  } catch {
    res.status(409).json({ error: "Такой никнейм или email уже занят." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const email = clean(req.body.email, 120).toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || user.status !== "active" || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(400).json({ error: "Неверный email или пароль." });
  }
  req.session.userId = user.id;
  db.prepare("INSERT OR IGNORE INTO user_settings(user_id) VALUES(?)").run(user.id);
  res.json({ user: publicUser(user) });
});

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/posts", (req, res) => {
  const q = clean(req.query.q, 100);
  const category = clean(req.query.category, 30);
  const where = [];
  const args = [];
  if (q) { where.push("(p.title LIKE ? OR p.body LIKE ? OR u.username LIKE ?)"); args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  if (category && category !== "Все") { where.push("p.category=?"); args.push(category); }
  const viewer=getUser(req.session.userId || 0);
  where.push("(COALESCE((SELECT private_profile FROM user_settings WHERE user_id=p.user_id),0)=0 OR p.user_id=? OR ?=1)");
  args.push(req.session.userId || 0, viewer && viewer.role === "admin" ? 1 : 0);
  const sql = `
    SELECT p.id,p.title,p.body,p.category,p.created_at,u.id user_id,u.username,
      (SELECT COUNT(*) FROM attachments a WHERE a.post_id=p.id) files,
      (SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) likes,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments,
      (SELECT COALESCE(SUM(v.value),0) FROM idea_votes v WHERE v.post_id=p.id) idea_score,
      EXISTS(SELECT 1 FROM reactions r WHERE r.post_id=p.id AND r.user_id=?) liked
    FROM posts p JOIN users u ON u.id=p.user_id
    ${where.length ? "WHERE " + where.join(" AND ") : ""}
    ORDER BY idea_score DESC, p.id DESC LIMIT 100`;
  const posts=db.prepare(sql).all(req.session.userId || 0, ...args).map(p=>({...p,reactions:db.prepare("SELECT reaction,COUNT(*) count FROM reactions WHERE post_id=? GROUP BY reaction").all(p.id),my_reaction:db.prepare("SELECT reaction FROM reactions WHERE post_id=? AND user_id=?").get(p.id,req.session.userId||0)?.reaction||null}));
  res.json({ posts });
});

app.post("/api/posts", requireAuth, postLimiter, (req, res) => {
  const title = clean(req.body.title, 100), body = clean(req.body.body, 4000);
  const categories = ["Идеи", "Проблемы", "Вопросы", "Жалобы", "Новости"];
  const category = categories.includes(req.body.category) ? req.body.category : "Идеи";
  if (title.length < 4 || body.length < 5) return res.status(400).json({ error: "Добавьте заголовок и описание." });
  const result = db.prepare("INSERT INTO posts(user_id,category,title,body) VALUES(?,?,?,?)").run(req.user.id, category, title, body);
  const pollQuestion=clean(req.body.pollQuestion,180), pollOptions=Array.isArray(req.body.pollOptions)?req.body.pollOptions.map(x=>clean(x,100)).filter(Boolean).slice(0,5):[];
  if(pollQuestion && pollOptions.length>=2){const poll=db.prepare("INSERT INTO post_polls(post_id,question) VALUES(?,?)").run(result.lastInsertRowid,pollQuestion);const add=db.prepare("INSERT INTO poll_options(poll_id,label) VALUES(?,?)");pollOptions.forEach(x=>add.run(poll.lastInsertRowid,x));}
  audit(req.user.id, "post.create", "post", result.lastInsertRowid);
  telegram(`🌞 <b>Новая публикация Sunshine Forum</b>\n${clean(title,100)}\nАвтор: ${clean(req.user.username,24)}`);
  res.json({ id: result.lastInsertRowid });
});

app.delete("/api/posts/:id", requireAuth, (req, res) => {
  const post = db.prepare("SELECT * FROM posts WHERE id=?").get(req.params.id);
  if (!post) return res.status(404).json({ error: "Публикация не найдена." });
  if (post.user_id !== req.user.id && req.user.role!=="admin") return res.status(403).json({ error: "Нет доступа." });
  db.prepare("DELETE FROM posts WHERE id=?").run(post.id);
  res.json({ ok: true });
});

app.get("/api/posts/:id", (req, res) => {
  const post = db.prepare(`SELECT p.*,u.username,u.id user_id,
    (SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) likes,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments,
    EXISTS(SELECT 1 FROM reactions r WHERE r.post_id=p.id AND r.user_id=?) liked,
    (SELECT COALESCE(SUM(v.value),0) FROM idea_votes v WHERE v.post_id=p.id) idea_score,
    (SELECT value FROM idea_votes v WHERE v.post_id=p.id AND v.user_id=?) my_idea_vote
    FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?`).get(req.session.userId || 0, req.session.userId || 0, req.params.id);
  if (!post) return res.status(404).json({ error: "Публикация не найдена." });
  const ownerPrivate=db.prepare("SELECT private_profile FROM user_settings WHERE user_id=?").get(post.user_id)?.private_profile===1;
  const viewer=getUser(req.session.userId || 0);
  if(ownerPrivate && Number(req.session.userId)!==post.user_id && viewer?.role !== "admin") return res.status(403).json({error:"Публикации этого пользователя доступны только ему и сотрудникам."});
  const comments = db.prepare(`SELECT c.*,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id`).all(post.id).map(c=>({...c,attachments:db.prepare("SELECT id,original_name,mime,size,'/uploads/'||stored_name url FROM attachments WHERE comment_id=?").all(c.id)}));
  const attachments=db.prepare("SELECT id,original_name,mime,size,'/uploads/'||stored_name url FROM attachments WHERE post_id=?").all(post.id);
  const poll=db.prepare("SELECT * FROM post_polls WHERE post_id=?").get(post.id);
  res.json({ post:{...post,reactions:db.prepare("SELECT reaction,COUNT(*) count FROM reactions WHERE post_id=? GROUP BY reaction").all(post.id),my_reaction:db.prepare("SELECT reaction FROM reactions WHERE post_id=? AND user_id=?").get(post.id,req.session.userId||0)?.reaction||null}, comments, attachments, poll:poll?{...poll,options:db.prepare("SELECT o.id,o.label,(SELECT COUNT(*) FROM poll_votes v WHERE v.option_id=o.id) votes FROM poll_options o WHERE o.poll_id=?").all(poll.id),myVote:db.prepare("SELECT option_id FROM poll_votes WHERE poll_id=? AND user_id=?").get(poll.id,req.session.userId||0)?.option_id||null}:null });
});

app.post("/api/posts/:id/react", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!db.prepare("SELECT id FROM posts WHERE id=?").get(id)) return res.status(404).json({ error: "Публикация не найдена." });
  const existing = db.prepare("SELECT 1 FROM reactions WHERE user_id=? AND post_id=?").get(req.user.id, id);
  if (existing) db.prepare("DELETE FROM reactions WHERE user_id=? AND post_id=?").run(req.user.id, id);
  else {
    db.prepare("INSERT INTO reactions(user_id,post_id,created_at) VALUES(?,?,CURRENT_TIMESTAMP)").run(req.user.id, id);
    const owner = db.prepare("SELECT user_id FROM posts WHERE id=?").get(id).user_id;
    if (owner !== req.user.id) notify(owner, `${req.user.username} оценил(а) вашу публикацию.`, "post", id);
  }
  const likes = db.prepare("SELECT COUNT(*) n FROM reactions WHERE post_id=?").get(id).n;
  io.emit("post:updated", { id, likes, comments: db.prepare("SELECT COUNT(*) n FROM comments WHERE post_id=?").get(id).n });
  res.json({ liked: !existing, likes });
});

app.post("/api/posts/:id/reactions", requireAuth, (req,res)=>{
  const id=Number(req.params.id), allowed=["heart","like","dislike","fire","happy"], reaction=String(req.body.reaction||"");
  if(!db.prepare("SELECT id FROM posts WHERE id=?").get(id))return res.status(404).json({error:"Публикация не найдена."});
  if(!allowed.includes(reaction))return res.status(400).json({error:"Неизвестная реакция."});
  const old=db.prepare("SELECT reaction FROM reactions WHERE user_id=? AND post_id=?").get(req.user.id,id);
  if(old?.reaction===reaction)db.prepare("DELETE FROM reactions WHERE user_id=? AND post_id=?").run(req.user.id,id);
  else db.prepare("INSERT INTO reactions(user_id,post_id,reaction,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,post_id) DO UPDATE SET reaction=excluded.reaction,created_at=CURRENT_TIMESTAMP").run(req.user.id,id,reaction);
  const counts=db.prepare("SELECT reaction,COUNT(*) count FROM reactions WHERE post_id=? GROUP BY reaction").all(id);
  res.json({mine:old?.reaction===reaction?null:reaction,counts});
});
app.post("/api/posts/:id/idea-vote", requireAuth, (req,res)=>{
  const id=Number(req.params.id),value=Number(req.body.value);
  if(![-1,1].includes(value))return res.status(400).json({error:"Выберите плюс или минус."});
  if(!db.prepare("SELECT id FROM posts WHERE id=?").get(id))return res.status(404).json({error:"Публикация не найдена."});
  const old=db.prepare("SELECT value FROM idea_votes WHERE user_id=? AND post_id=?").get(req.user.id,id);
  if(old?.value===value)db.prepare("DELETE FROM idea_votes WHERE user_id=? AND post_id=?").run(req.user.id,id);
  else db.prepare("INSERT INTO idea_votes(user_id,post_id,value) VALUES(?,?,?) ON CONFLICT(user_id,post_id) DO UPDATE SET value=excluded.value").run(req.user.id,id,value);
  res.json({mine:old?.value===value?0:value,score:db.prepare("SELECT COALESCE(SUM(value),0) score FROM idea_votes WHERE post_id=?").get(id).score});
});

app.post("/api/posts/:id/comments", requireAuth, postLimiter, (req, res) => {
  const body = clean(req.body.body, 1000);
  const post = db.prepare("SELECT * FROM posts WHERE id=?").get(req.params.id);
  if (!post) return res.status(404).json({ error: "Публикация не найдена." });
  const ids=Array.isArray(req.body.attachmentIds)?req.body.attachmentIds.map(Number).filter(Number.isInteger):[];
  if (body.length < 1 && ids.length < 1) return res.status(400).json({ error: "Добавьте текст или вложение." });
  const result=db.prepare("INSERT INTO comments(post_id,user_id,body) VALUES(?,?,?)").run(post.id, req.user.id, body);
  for(const aid of ids)db.prepare("UPDATE attachments SET comment_id=? WHERE id=? AND owner_id=? AND post_id IS NULL AND report_id IS NULL AND comment_id IS NULL").run(result.lastInsertRowid,aid,req.user.id);
  if (post.user_id !== req.user.id) notify(post.user_id, `${req.user.username} прокомментировал(а) вашу публикацию.`, "post", post.id);
  notifyMentions(body,req.user,"в комментарии","post",post.id);
  const counts = { id: post.id, likes: db.prepare("SELECT COUNT(*) n FROM reactions WHERE post_id=?").get(post.id).n, comments: db.prepare("SELECT COUNT(*) n FROM comments WHERE post_id=?").get(post.id).n };
  io.emit("post:updated", counts);
  res.json({ ok: true, commentId:result.lastInsertRowid, ...counts });
});

app.get("/api/posts/:id/poll",requireAuth,(req,res)=>{const poll=db.prepare("SELECT * FROM post_polls WHERE post_id=?").get(req.params.id);if(!poll)return res.json({poll:null});const options=db.prepare("SELECT o.id,o.label,(SELECT COUNT(*) FROM poll_votes v WHERE v.option_id=o.id) votes FROM poll_options o WHERE o.poll_id=?").all(poll.id);const vote=db.prepare("SELECT option_id FROM poll_votes WHERE poll_id=? AND user_id=?").get(poll.id,req.user.id);res.json({poll:{...poll,options,myVote:vote?.option_id||null}});});
app.post("/api/posts/:id/poll/vote",requireAuth,(req,res)=>{const poll=db.prepare("SELECT * FROM post_polls WHERE post_id=?").get(req.params.id);if(!poll)return res.status(404).json({error:"Опрос не найден."});const option=db.prepare("SELECT id FROM poll_options WHERE id=? AND poll_id=?").get(Number(req.body.optionId),poll.id);if(!option)return res.status(400).json({error:"Выберите вариант ответа."});db.prepare("INSERT INTO poll_votes(poll_id,option_id,user_id) VALUES(?,?,?) ON CONFLICT(poll_id,user_id) DO UPDATE SET option_id=excluded.option_id").run(poll.id,option.id,req.user.id);res.json({ok:true});});

app.get("/api/profile/:id", (req, res) => {
  const user = db.prepare("SELECT id,username,bio,avatar,role,created_at FROM users WHERE id=?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "Пользователь не найден." });
  const privateProfile = db.prepare("SELECT private_profile FROM user_settings WHERE user_id=?").get(user.id)?.private_profile === 1;
  if (privateProfile && (!req.session.userId || Number(req.session.userId) !== user.id) && getUser(req.session.userId || 0)?.role !== "admin") return res.status(403).json({ error: "Этот профиль закрыт владельцем." });
  const posts = db.prepare("SELECT p.*,(SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) likes,(SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments FROM posts p WHERE user_id=? ORDER BY id DESC").all(user.id);
  const stats = db.prepare("SELECT (SELECT COUNT(*) FROM posts WHERE user_id=?) posts,(SELECT COUNT(*) FROM reactions r JOIN posts p ON p.id=r.post_id WHERE p.user_id=?) reputation").get(user.id,user.id);
  res.json({ user, posts, stats });
});


app.get("/api/profile/:id/activity",requireAuth,(req,res)=>{
  const id=Number(req.params.id);
  if(id!==req.user.id && req.user.role!=="admin") return res.status(403).json({error:"История активности доступна только владельцу профиля."});
  const comments=db.prepare("SELECT c.id,c.body,c.created_at,p.id post_id,p.title FROM comments c JOIN posts p ON p.id=c.post_id WHERE c.user_id=? ORDER BY c.id DESC LIMIT 100").all(id).map(c=>({...c,attachments:db.prepare("SELECT id,original_name,mime,size,'/uploads/'||stored_name url FROM attachments WHERE comment_id=? ORDER BY id").all(c.id)}));
  const reactions=db.prepare("SELECT r.post_id,r.reaction,r.created_at,p.title,p.created_at post_created_at,u.username FROM reactions r JOIN posts p ON p.id=r.post_id JOIN users u ON u.id=p.user_id WHERE r.user_id=? ORDER BY r.created_at DESC,r.post_id DESC LIMIT 100").all(id);
  res.json({comments,reactions});
});
app.patch("/api/profile", requireAuth, (req, res) => {
  const bio = clean(req.body.bio, 180);
  const username = clean(req.body.username || req.user.username, 24);
  if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) return res.status(400).json({ error: "Ник: 3–24 символа, буквы, цифры, _ или -." });
  if (db.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE AND id<>?").get(username, req.user.id)) return res.status(409).json({ error: "Этот никнейм уже занят." });
  db.prepare("UPDATE users SET bio=?,username=? WHERE id=?").run(bio, username, req.user.id);
  audit(req.user.id, "profile.update", "user", req.user.id);
  res.json({ user: publicUser(getUser(req.user.id)) });
});

app.get("/api/notifications", requireAuth, (req, res) => {
  // Resolve older notification formats as well as current post/report/chat links.
  const notifications = db.prepare(`SELECT n.*,
    CASE
      WHEN n.target_type IN ('post','report','chat','profile','user') THEN n.target_type
      WHEN n.target_type IN ('comment','post_comment','reply') THEN 'post'
      ELSE '' END AS resolved_type,
    CASE
      WHEN n.target_type IN ('comment','post_comment','reply') THEN (SELECT c.post_id FROM comments c WHERE c.id=n.target_id)
      ELSE n.target_id END AS resolved_id
    FROM notifications n WHERE n.user_id=? ORDER BY n.id DESC LIMIT 50`).all(req.user.id);
  res.json({ notifications: notifications.map(n => ({...n, target_type: n.resolved_type, target_id: n.resolved_id})) });
});
app.post("/api/notifications/read", requireAuth, (req, res) => {
  db.prepare("UPDATE notifications SET read=1 WHERE user_id=?").run(req.user.id);
  res.json({ ok: true });
});

app.post("/api/reports", requireAuth, (req, res) => {
  const topic = clean(req.body.topic, 80), body = clean(req.body.body, 2000);
  if (!topic || body.length < 10) return res.status(400).json({ error: "Выберите тему и подробно опишите обращение." });
  const result=db.prepare("INSERT INTO reports(user_id,topic,body) VALUES(?,?,?)").run(req.user.id, topic, body);
  audit(req.user.id,"report.create","report",result.lastInsertRowid);
  telegram(`✉️ <b>Новое обращение</b>\nТема: ${clean(topic,80)}\nОт: ${clean(req.user.username,24)}`);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.get("/api/achievements/:id",requireAuth,(req,res)=>{
  const id=Number(req.params.id), user=getUser(id); if(!user)return res.status(404).json({error:"Пользователь не найден."});
  const privateProfile=db.prepare("SELECT private_profile FROM user_settings WHERE user_id=?").get(id)?.private_profile===1;
  if(privateProfile && id!==req.user.id && req.user.role!=="admin") return res.status(403).json({error:"Достижения этого профиля скрыты."});
  const posts=db.prepare("SELECT COUNT(*) n FROM posts WHERE user_id=?").get(id).n;
  const comments=db.prepare("SELECT COUNT(*) n FROM comments WHERE user_id=?").get(id).n;
  const likes=db.prepare("SELECT COUNT(*) n FROM reactions r JOIN posts p ON p.id=r.post_id WHERE p.user_id=?").get(id).n;
  const achievements=[
    {id:"welcome",title:"Первый лучик",description:"Присоединился к Sunshine Forum",icon:"🌤️",earned:true},
    {id:"first-post",title:"Первая публикация",description:"Создал первую тему",icon:"📝",earned:posts>=1},
    {id:"writer",title:"Автор идей",description:"Опубликовал 5 тем",icon:"✍️",earned:posts>=5},
    {id:"first-comment",title:"В диалоге",description:"Оставил первый комментарий",icon:"💬",earned:comments>=1},
    {id:"talkative",title:"Активный участник",description:"Оставил 20 комментариев",icon:"🗨️",earned:comments>=20},
    {id:"popular",title:"Тёплый отклик",description:"Получил 10 реакций на публикации",icon:"💜",earned:likes>=10}
  ];
  if(["admin","moderator"].includes(user.role)){
    const actions=db.prepare("SELECT COUNT(*) n FROM audit_logs WHERE actor_id=? AND action IN ('chat.message.delete','user.ban','chat.mute','chat.unmute','report.status')").get(id).n;
    achievements.push({id:"staff",title:"Хранитель сообщества",description:"Сотрудник Sunshine Forum",icon:"🛡️",earned:true},{id:"helper",title:"На страже порядка",description:"Выполнил 10 действий модерации",icon:"⭐",earned:actions>=10});
  }
  res.json({achievements,counts:{posts,comments,likes}});
});

app.post("/api/chat/message",requireAuth,upload.array("files",5),(req,res)=>{
 const body=clean(req.body.body,800);const pollQuestion=clean(req.body.pollQuestion,180);let pollOptions=[];try{pollOptions=JSON.parse(req.body.pollOptions||"[]").map(x=>clean(x,100)).filter(Boolean).slice(0,5)}catch{}
 const mute=db.prepare("SELECT muted_until FROM chat_mutes WHERE user_id=? AND muted_until>datetime('now')").get(req.user.id);if(mute)return res.status(403).json({error:"Вам временно запрещено писать в общий чат."});
 if(!body && !(req.files||[]).length && !(pollQuestion&&pollOptions.length>=2))return res.status(400).json({error:"Добавьте текст, файл или опрос."});
 const r=db.prepare("INSERT INTO messages(user_id,body) VALUES(?,?)").run(req.user.id,body||"");const messageId=r.lastInsertRowid;
 for(const f of req.files||[]){const a=db.prepare("INSERT INTO attachments(owner_id,original_name,stored_name,mime,size) VALUES(?,?,?,?,?)").run(req.user.id,clean(f.originalname,180),f.filename,f.mimetype,f.size);db.prepare("INSERT INTO chat_attachments(message_id,attachment_id) VALUES(?,?)").run(messageId,a.lastInsertRowid);}
 let poll=null;if(pollQuestion&&pollOptions.length>=2){const pr=db.prepare("INSERT INTO chat_polls(message_id,question) VALUES(?,?)").run(messageId,pollQuestion);const add=db.prepare("INSERT INTO chat_poll_options(poll_id,label) VALUES(?,?)");pollOptions.forEach(x=>add.run(pr.lastInsertRowid,x));poll={id:pr.lastInsertRowid,question:pollQuestion,options:db.prepare("SELECT id,label FROM chat_poll_options WHERE poll_id=?").all(pr.lastInsertRowid)};}
 const attachments=db.prepare("SELECT a.id,a.original_name,a.mime,a.size,'/uploads/'||a.stored_name url FROM chat_attachments ca JOIN attachments a ON a.id=ca.attachment_id WHERE ca.message_id=?").all(messageId);
 const message={id:messageId,body:body||"",username:req.user.username,user_id:req.user.id,role:req.user.role,created_at:new Date().toISOString(),attachments,poll};io.emit("chat:message",message);notifyMentions(body,req.user,"в общем чате","chat",messageId);res.json({ok:true,id:messageId});
});
app.post("/api/chat/:id/reaction",requireAuth,(req,res)=>{
 const id=Number(req.params.id),allowed=["heart","like","dislike","fire","happy"],reaction=String(req.body.reaction||"");
 if(!db.prepare("SELECT id FROM messages WHERE id=?").get(id))return res.status(404).json({error:"Сообщение не найдено."});
 if(!allowed.includes(reaction))return res.status(400).json({error:"Неизвестная реакция."});
 const old=db.prepare("SELECT reaction FROM chat_reactions WHERE user_id=? AND message_id=?").get(req.user.id,id);
 if(old?.reaction===reaction)db.prepare("DELETE FROM chat_reactions WHERE user_id=? AND message_id=?").run(req.user.id,id);
 else db.prepare("INSERT INTO chat_reactions(user_id,message_id,reaction) VALUES(?,?,?) ON CONFLICT(user_id,message_id) DO UPDATE SET reaction=excluded.reaction").run(req.user.id,id,reaction);
 const counts=db.prepare("SELECT reaction,COUNT(*) count FROM chat_reactions WHERE message_id=? GROUP BY reaction").all(id);
 res.json({mine:old?.reaction===reaction?null:reaction,counts});
});
app.post("/api/chat/polls/:id/vote",requireAuth,(req,res)=>{const poll=db.prepare("SELECT * FROM chat_polls WHERE id=?").get(req.params.id);if(!poll)return res.status(404).json({error:"Опрос не найден."});const option=db.prepare("SELECT id FROM chat_poll_options WHERE id=? AND poll_id=?").get(Number(req.body.optionId),poll.id);if(!option)return res.status(400).json({error:"Выберите вариант."});db.prepare("INSERT INTO chat_poll_votes(poll_id,option_id,user_id) VALUES(?,?,?) ON CONFLICT(poll_id,user_id) DO UPDATE SET option_id=excluded.option_id").run(poll.id,option.id,req.user.id);res.json({ok:true});});
app.get("/api/chat/stats", requireAuth, (req,res)=>{
  res.json({ totalUsers: db.prepare("SELECT COUNT(*) n FROM users WHERE status='active'").get().n, onlineUsers: onlineSockets.size });
});

app.get("/api/chat", requireAuth, (req, res) => {
  const messages = db.prepare("SELECT m.id,m.body,m.created_at,u.username,u.id user_id,u.role FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC LIMIT 80").all().reverse().map(m=>({...m,attachments:db.prepare("SELECT a.id,a.original_name,a.mime,a.size,'/uploads/'||a.stored_name url FROM chat_attachments ca JOIN attachments a ON a.id=ca.attachment_id WHERE ca.message_id=?").all(m.id),poll:(()=>{const p=db.prepare("SELECT * FROM chat_polls WHERE message_id=?").get(m.id);if(!p)return null;return {...p,options:db.prepare("SELECT o.id,o.label,(SELECT COUNT(*) FROM chat_poll_votes v WHERE v.option_id=o.id) votes FROM chat_poll_options o WHERE o.poll_id=?").all(p.id),myVote:db.prepare("SELECT option_id FROM chat_poll_votes WHERE poll_id=? AND user_id=?").get(p.id,req.user.id)?.option_id||null};})(),reactions:db.prepare("SELECT reaction,COUNT(*) count FROM chat_reactions WHERE message_id=? GROUP BY reaction").all(m.id),myReaction:db.prepare("SELECT reaction FROM chat_reactions WHERE message_id=? AND user_id=?").get(m.id,req.user.id)?.reaction||null}));
  const mute = db.prepare("SELECT muted_until FROM chat_mutes WHERE user_id=? AND muted_until > datetime('now')").get(req.user.id);
  res.json({ messages, mutedUntil: mute?.muted_until || null });
});
app.get("/api/chat/users",requireAuth,(req,res)=>{
  const users=db.prepare("SELECT u.id,u.username,u.avatar,u.role,COALESCE(s.private_profile,0) private_profile FROM users u LEFT JOIN user_settings s ON s.user_id=u.id WHERE u.status='active' ORDER BY u.username LIMIT 300").all()
    .filter(u=>!u.private_profile)
    .map(({private_profile,...u})=>({...u,online:onlineSockets.has(u.id)}));
  res.json({users});
});

app.get("/api/admin/overview", requireAuth, requireStaff, (req, res) => {
  const users = db.prepare("SELECT id,username,email,role,status,created_at FROM users ORDER BY id DESC LIMIT 200").all();
  const reports = db.prepare("SELECT r.*,u.username FROM reports r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 100").all();
  const posts = db.prepare("SELECT p.id,p.title,p.category,p.created_at,u.username FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100").all();
  const stats = {
    users: db.prepare("SELECT COUNT(*) n FROM users").get().n,
    posts: db.prepare("SELECT COUNT(*) n FROM posts").get().n,
    reports: db.prepare("SELECT COUNT(*) n FROM reports WHERE status='Новая'").get().n,
    comments: db.prepare("SELECT COUNT(*) n FROM comments").get().n,
    reactions: db.prepare("SELECT COUNT(*) n FROM reactions").get().n,
    activeUsers: db.prepare("SELECT COUNT(*) n FROM users WHERE status='active'").get().n
  };
  res.json({ users, reports, posts, stats });
});
app.get("/api/admin/users/blocked", requireAuth, requireStaff, (req,res) => {
  const users = db.prepare("SELECT id,username,email,role,status,created_at FROM users WHERE status='blocked' ORDER BY id DESC").all();
  res.json({users});
});
app.post("/api/admin/users/:id/unban", requireAuth, requireStaff, (req,res) => {
  const id=Number(req.params.id), target=getUser(id);
  if(!target) return res.status(404).json({error:"Пользователь не найден."});
  if(target.role!=="user" && req.user.role!=="admin") return res.status(403).json({error:"Снимать блокировку с сотрудников может только администратор."});
  if(target.status!=="blocked") return res.status(400).json({error:"Пользователь уже не заблокирован."});
  db.prepare("UPDATE users SET status='active' WHERE id=?").run(id);
  audit(req.user.id,"user.unban","user",id);
  res.json({ok:true});
});
app.patch("/api/admin/users/:id", requireAuth, requireAdmin, (req, res) => {
  const status = req.body.status === "blocked" ? "blocked" : "active";
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: "Нельзя изменить статус собственного аккаунта." });
  db.prepare("UPDATE users SET status=? WHERE id=?").run(status, req.params.id);
  audit(req.user.id, "user.status", "user", Number(req.params.id), status);
  res.json({ ok: true });
});
app.patch("/api/admin/reports/:id", requireAuth, requireStaff, (req, res) => {
  const status = clean(req.body.status, 30);
  if (!["В работе", "Решена", "Отклонена"].includes(status)) return res.status(400).json({ error: "Некорректный статус." });
  const report=db.prepare("SELECT user_id FROM reports WHERE id=?").get(req.params.id);
  db.prepare("UPDATE reports SET status=? WHERE id=?").run(status, req.params.id);
  if(report) notify(report.user_id, `Статус вашего обращения #${req.params.id}: ${status}.`, "report", Number(req.params.id));
  audit(req.user.id, "report.status", "report", Number(req.params.id), status);
  res.json({ ok: true });
});


// Profile avatar, settings, report conversation, uploads and audit/statistics.
app.post("/api/attachments",requireAuth,upload.array("files",5),(req,res)=>{ const files=req.files||[]; const saved=files.map(f=>{const r=db.prepare("INSERT INTO attachments(owner_id,original_name,stored_name,mime,size) VALUES(?,?,?,?,?)").run(req.user.id,clean(f.originalname,180),f.filename,f.mimetype,f.size);return {id:r.lastInsertRowid,name:clean(f.originalname,180),url:"/uploads/"+f.filename,mime:f.mimetype,size:f.size};}); res.json({files:saved}); });
app.post("/api/attachments/attach",requireAuth,(req,res)=>{const ids=Array.isArray(req.body.ids)?req.body.ids.map(Number).filter(Number.isInteger):[];const type=["report","comment","post"].includes(req.body.type)?req.body.type:"post";const target=Number(req.body.target);const exists=type==="post"?db.prepare("SELECT user_id FROM posts WHERE id=?").get(target):type==="report"?db.prepare("SELECT user_id FROM reports WHERE id=?").get(target):db.prepare("SELECT user_id FROM comments WHERE id=?").get(target);if(!exists || (type==="post"||type==="comment"?exists.user_id!==req.user.id:(exists.user_id!==req.user.id && req.user.role!=="admin")))return res.status(403).json({error:"Нет доступа."});const col=type+"_id";for(const id of ids)db.prepare(`UPDATE attachments SET ${col}=? WHERE id=? AND owner_id=? AND post_id IS NULL AND report_id IS NULL AND comment_id IS NULL`).run(target,id,req.user.id);res.json({ok:true});});
app.post("/api/avatar", requireAuth, upload.single("avatar"), (req,res) => {
  if (!req.file) return res.status(400).json({error:"Выберите изображение."});
  if (!/^image\/(png|jpeg|webp|gif)$/.test(req.file.mimetype)) { fs.unlinkSync(req.file.path); return res.status(400).json({error:"Аватар должен быть изображением."}); }
  const old = getUser(req.user.id).avatar;
  db.prepare("UPDATE users SET avatar=? WHERE id=?").run("/uploads/"+req.file.filename, req.user.id);
  if (old && old.startsWith("/uploads/")) { const oldPath=path.join(uploadDir,path.basename(old)); if(fs.existsSync(oldPath))fs.unlinkSync(oldPath); }
  audit(req.user.id,"profile.avatar","user",req.user.id);
  res.json({user:publicUser(getUser(req.user.id))});
});
app.get("/uploads/:filename",requireAuth,(req,res)=>{ const filename=path.basename(req.params.filename); const file=db.prepare("SELECT * FROM attachments WHERE stored_name=?").get(filename); const avatarOwner=db.prepare("SELECT u.id,COALESCE(s.private_profile,0) private_profile FROM users u LEFT JOIN user_settings s ON s.user_id=u.id WHERE u.avatar=?").get("/uploads/"+filename); if(file){const inChat=db.prepare("SELECT 1 FROM chat_attachments WHERE attachment_id=?").get(file.id);if(file.report_id){const report=db.prepare("SELECT user_id FROM reports WHERE id=?").get(file.report_id);if(!report || (report.user_id!==req.user.id && !["admin","moderator"].includes(req.user.role)))return res.sendStatus(403);}else if(file.comment_id){const c=db.prepare("SELECT c.user_id,p.user_id post_owner,COALESCE(us.private_profile,0) private_profile FROM comments c JOIN posts p ON p.id=c.post_id LEFT JOIN user_settings us ON us.user_id=p.user_id WHERE c.id=?").get(file.comment_id);if(!c || (c.private_profile && c.post_owner!==req.user.id && c.user_id!==req.user.id && req.user.role!=="admin"))return res.sendStatus(403);}else if(file.post_id){const owner=db.prepare("SELECT p.user_id,COALESCE(us.private_profile,0) private_profile FROM posts p LEFT JOIN user_settings us ON us.user_id=p.user_id WHERE p.id=?").get(file.post_id);if(!owner || (owner.private_profile && owner.user_id!==req.user.id && req.user.role!=="admin"))return res.sendStatus(403);}else if(!inChat)return res.sendStatus(404);}else if(!avatarOwner)return res.sendStatus(404);else if(avatarOwner.private_profile && avatarOwner.id!==req.user.id && req.user.role!=="admin")return res.sendStatus(403); res.setHeader("X-Content-Type-Options","nosniff"); res.setHeader("Content-Disposition", "inline"); res.sendFile(path.join(uploadDir,filename)); });
app.get("/api/settings",requireAuth,(req,res)=>{ db.prepare("INSERT OR IGNORE INTO user_settings(user_id) VALUES(?)").run(req.user.id); res.json({settings:db.prepare("SELECT notify_likes,notify_comments,notify_reports,private_profile FROM user_settings WHERE user_id=?").get(req.user.id)}); });
app.patch("/api/settings",requireAuth,(req,res)=>{ const keys=["notify_likes","notify_comments","notify_reports","private_profile"]; const vals=keys.map(k=>req.body[k]?1:0); db.prepare("INSERT INTO user_settings(user_id,notify_likes,notify_comments,notify_reports,private_profile) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET notify_likes=excluded.notify_likes,notify_comments=excluded.notify_comments,notify_reports=excluded.notify_reports,private_profile=excluded.private_profile").run(req.user.id,...vals); res.json({ok:true}); });
app.post("/api/reports/:id/messages",requireAuth,(req,res)=>{ const report=db.prepare("SELECT * FROM reports WHERE id=?").get(req.params.id); if(!report)return res.status(404).json({error:"Обращение не найдено."}); if(report.user_id!==req.user.id && req.user.role!=="admin" && req.user.role!=="moderator")return res.status(403).json({error:"Нет доступа."}); const body=clean(req.body.body,2000); if(!body)return res.status(400).json({error:"Введите сообщение."}); db.prepare("INSERT INTO report_messages(report_id,user_id,body) VALUES(?,?,?)").run(report.id,req.user.id,body); if(report.user_id!==req.user.id){ notify(report.user_id,"Администрация ответила на ваше обращение.","report",report.id); db.prepare("UPDATE reports SET status=CASE WHEN status='Новая' THEN 'В работе' ELSE status END WHERE id=?").run(report.id); } else { const staff=db.prepare("SELECT id FROM users WHERE role IN ('admin','moderator') AND status='active'").all(); staff.forEach(x=>notify(x.id,"Новое сообщение в обращении #"+report.id+".","report",report.id)); } io.to("report:"+report.id).emit("report:message",{reportId:report.id}); res.json({ok:true}); });
app.get("/api/reports/:id/messages",requireAuth,(req,res)=>{ const report=db.prepare("SELECT * FROM reports WHERE id=?").get(req.params.id); if(!report)return res.status(404).json({error:"Обращение не найдено."}); if(report.user_id!==req.user.id && req.user.role!=="admin")return res.status(403).json({error:"Нет доступа."}); res.json({messages:[{id:0,report_id:report.id,user_id:report.user_id,username:db.prepare("SELECT username FROM users WHERE id=?").get(report.user_id).username,body:report.body,created_at:report.created_at,initial:true}],...{attachments:db.prepare("SELECT id,original_name,mime,size,'/uploads/'||stored_name url FROM attachments WHERE report_id=? ORDER BY id").all(report.id)},...{replies:db.prepare("SELECT m.*,u.username FROM report_messages m JOIN users u ON u.id=m.user_id WHERE report_id=? ORDER BY m.id").all(report.id)}}); });
// Search users for staff and list a user's own support tickets.
app.get("/api/reports",requireAuth,(req,res)=>{
  const rows = req.user.role === "admin" || req.user.role === "moderator"
    ? db.prepare("SELECT r.*,u.username FROM reports r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 100").all()
    : db.prepare("SELECT * FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.user.id);
  res.json({reports:rows});
});
app.get("/api/admin/users/search",requireAuth,requireStaff,(req,res)=>{
  const q=clean(req.query.q,40);
  if(q.length<2) return res.json({users:[]});
  const users=db.prepare("SELECT id,username,email,role,status,created_at FROM users WHERE username LIKE ? COLLATE NOCASE ORDER BY username LIMIT 30").all(`%${q}%`);
  res.json({users});
});
app.delete("/api/chat/:id",requireAuth,requireStaff,(req,res)=>{
  const msg=db.prepare("SELECT m.*,u.role FROM messages m JOIN users u ON u.id=m.user_id WHERE m.id=?").get(req.params.id);
  if(!msg) return res.status(404).json({error:"Сообщение не найдено."});
  if(msg.role!=="user" && req.user.role!=="admin") return res.status(403).json({error:"Модератор не может удалять сообщения администрации."});
  db.prepare("DELETE FROM messages WHERE id=?").run(msg.id);
  audit(req.user.id,"chat.message.delete","message",msg.id);
  io.emit("chat:deleted",{id:msg.id});
  res.json({ok:true});
});
app.post("/api/admin/users/:id/ban",requireAuth,requireStaff,(req,res)=>{
  const id=Number(req.params.id), target=getUser(id);
  if(!target) return res.status(404).json({error:"Пользователь не найден."});
  if(id===req.user.id) return res.status(400).json({error:"Нельзя заблокировать собственный аккаунт."});
  if(target.role==="admin") return res.status(403).json({error:"Нельзя заблокировать администратора."});
  if(req.user.role==="moderator" && target.role!=="user") return res.status(403).json({error:"Модератор может блокировать только обычных пользователей."});
  const reason=clean(req.body.reason,200);
  db.prepare("UPDATE users SET status='blocked' WHERE id=?").run(id);
  audit(req.user.id,"user.ban","user",id,reason);
  io.to("user:"+id).emit("account:blocked",{reason});
  res.json({ok:true});
});
app.post("/api/admin/users/:id/mute",requireAuth,requireStaff,(req,res)=>{
  const id=Number(req.params.id), target=getUser(id);
  if(!target) return res.status(404).json({error:"Пользователь не найден."});
  if(id===req.user.id) return res.status(400).json({error:"Нельзя ограничить чат самому себе."});
  if(target.role!=="user") return res.status(403).json({error:"Модераторы могут выдавать мут только обычным пользователям."});
  const minutes=[5,15,30,60,180,360,1440,10080].includes(Number(req.body.minutes))?Number(req.body.minutes):15;
  const until=new Date(Date.now()+minutes*60000).toISOString().slice(0,19).replace('T',' ');
  const reason=clean(req.body.reason||"Нарушение правил чата",200);
  db.prepare("INSERT INTO chat_mutes(user_id,moderator_id,muted_until,reason) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET moderator_id=excluded.moderator_id,muted_until=excluded.muted_until,reason=excluded.reason,created_at=CURRENT_TIMESTAMP").run(id,req.user.id,until,reason);
  audit(req.user.id,"chat.mute","user",id,`${minutes} минут: ${reason}`);
  io.to("user:"+id).emit("chat:muted",{until,reason});
  res.json({ok:true,mutedUntil:until});
});
app.delete("/api/admin/users/:id/mute",requireAuth,requireStaff,(req,res)=>{
  const id=Number(req.params.id),target=getUser(id);
  if(!target) return res.status(404).json({error:"Пользователь не найден."});
  if(target.role!=="user") return res.status(403).json({error:"Нельзя снять ограничение с сотрудника через эту функцию."});
  db.prepare("DELETE FROM chat_mutes WHERE user_id=?").run(id); audit(req.user.id,"chat.unmute","user",id); io.to("user:"+id).emit("chat:unmuted",{}); res.json({ok:true});
});
app.get("/api/admin/audit",requireAuth,requireStaff,(req,res)=>{ res.json({logs:db.prepare("SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 150").all()}); });
app.patch("/api/admin/users/:id/role",requireAuth,requireAdmin,(req,res)=>{ const role=["user","moderator","admin"].includes(req.body.role)?req.body.role:null; if(!role)return res.status(400).json({error:"Неизвестная роль."}); if(Number(req.params.id)===req.user.id)return res.status(400).json({error:"Нельзя изменить собственную роль."}); db.prepare("UPDATE users SET role=? WHERE id=?").run(role,req.params.id); audit(req.user.id,"user.role","user",Number(req.params.id),role); res.json({ok:true}); });
app.get("/api/admin/stats",requireAuth,requireAdmin,(req,res)=>{ res.json({daily:db.prepare("SELECT date(created_at) day,COUNT(*) count FROM users WHERE created_at>=datetime('now','-14 days') GROUP BY date(created_at) ORDER BY day").all(), totals:{users:db.prepare("SELECT COUNT(*) n FROM users").get().n,posts:db.prepare("SELECT COUNT(*) n FROM posts").get().n,comments:db.prepare("SELECT COUNT(*) n FROM comments").get().n,reactions:db.prepare("SELECT COUNT(*) n FROM reactions").get().n,reports:db.prepare("SELECT COUNT(*) n FROM reports").get().n}}); });
app.post("/api/telegram/webhook",async(req,res)=>{ const secret=process.env.TELEGRAM_WEBHOOK_SECRET; if(!secret||req.get("x-telegram-bot-api-secret-token")!==secret)return res.sendStatus(403); const msg=req.body?.message; if(msg?.text==="/start") await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({chat_id:msg.chat.id,text:"Sunshine Forum подключён. Уведомления о новых публикациях и обращениях будут приходить в настроенный чат."})}); res.sendStatus(200); });

io.engine.use(sessionMiddleware);
io.use((socket, next) => {
  const user = socket.request.session.userId && getUser(socket.request.session.userId);
  if (!user || user.status !== "active") return next(new Error("Необходим вход в аккаунт."));
  socket.user = publicUser(user);
  next();
});
io.on("connection", socket => {
  const uid=socket.user.id;
  onlineSockets.set(uid,(onlineSockets.get(uid)||0)+1);
  io.emit("presence:update",{onlineUsers:onlineSockets.size});
  socket.join("user:" + socket.user.id);
  socket.on("chat:send", raw => {
    const body = clean(raw, 800);
    if (!body) return;
    const mute=db.prepare("SELECT muted_until FROM chat_mutes WHERE user_id=?").get(socket.user.id);
    if(mute && new Date(mute.muted_until.replace(' ','T')+'Z')>new Date()) { socket.emit("chat:error",{message:"Вам временно запрещено писать в общий чат до "+mute.muted_until+" UTC."}); return; }
    if(mute) db.prepare("DELETE FROM chat_mutes WHERE user_id=?").run(socket.user.id);
    const result = db.prepare("INSERT INTO messages(user_id,body) VALUES(?,?)").run(socket.user.id, body);
    const message = { id: result.lastInsertRowid, body, username: socket.user.username, user_id: socket.user.id, role: socket.user.role, created_at: new Date().toISOString() };
    io.emit("chat:message", message);
    notifyMentions(body,socket.user,"в общем чате","chat",result.lastInsertRowid);
  });
  socket.on("disconnect", () => {
    const left=(onlineSockets.get(uid)||1)-1;
    if(left<=0) onlineSockets.delete(uid); else onlineSockets.set(uid,left);
    io.emit("presence:update",{onlineUsers:onlineSockets.size});
  });
});

app.use((err,req,res,next)=>{ if(err instanceof multer.MulterError) return res.status(400).json({error:err.code==="LIMIT_FILE_SIZE"?"Файл слишком большой (максимум 25 МБ).":"Слишком много файлов или неверный запрос."}); if(err) return res.status(400).json({error:err.message||"Ошибка загрузки."}); next(); });

async function seedAdmin() {
  const email = clean(process.env.ADMIN_EMAIL, 120).toLowerCase();
  const password = process.env.ADMIN_PASSWORD || "";
  if (!email || password.length < 12) return;
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (!existing) {
    const hash = await bcrypt.hash(password, 12);
    db.prepare("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')")
      .run(clean(process.env.ADMIN_NAME || "Admin",24), email, hash);
    console.log("Initial administrator created.");
  } else {
    db.prepare("UPDATE users SET role='admin' WHERE id=?").run(existing.id);
  }
}

seedAdmin().then(() => {
  server.listen(PORT, () => console.log(`Sunshine Forum is running on port ${PORT}`));
}).catch(err => { console.error(err); process.exit(1); });
