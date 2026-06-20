// ============================================================================
// PlexxoTalk Server
// Express + Socket.io + better-sqlite3, all backend logic in this one file.
//
// IMPORTANT (read this before assuming "the server can read messages"):
// All message text, voice notes, images, videos and PDFs are encrypted in the
// BROWSER before they ever reach this server (AES-256-GCM, with the AES key
// itself wrapped per-recipient using RSA-OAEP public keys). This server only
// ever stores/relays ciphertext + IVs. It has no way to decrypt content,
// because it never has any user's private key in usable form (private keys
// are stored only in an encrypted blob that needs the user's password to
// unlock, and that unlocking happens client-side only).
// ============================================================================

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const http = require('http');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (JWT_SECRET === 'dev-secret-change-me') {
  console.warn('[WARN] Using default JWT_SECRET. Set JWT_SECRET in your environment before deploying.');
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
const AVATAR_DIR = path.join(__dirname, 'uploads', 'avatars');
const FILES_DIR = path.join(__dirname, 'uploads', 'files');
for (const d of [DATA_DIR, AVATAR_DIR, FILES_DIR]) fs.mkdirSync(d, { recursive: true });

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------
const db = new Database(path.join(DATA_DIR, 'plexxotalk.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  public_key TEXT NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  pk_salt TEXT NOT NULL,
  pk_iv TEXT NOT NULL,
  avatar_path TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK(type IN ('dm','group','channel')),
  name TEXT,
  avatar_path TEXT,
  is_public INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS room_members (
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  encrypted_room_key TEXT,
  key_iv TEXT,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  room_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('text','image','video','audio','pdf')),
  ciphertext TEXT,
  iv TEXT,
  file_path TEXT,
  file_size INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, created_at);
CREATE INDEX IF NOT EXISTS idx_members_user ON room_members(user_id);
`);

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use('/uploads/avatars', express.static(AVATAR_DIR));
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function signToken(user) {
  return jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.uid;
    req.username = payload.username;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    name: u.name,
    username: u.username,
    publicKey: u.public_key,
    avatarUrl: u.avatar_path ? `/uploads/avatars/${path.basename(u.avatar_path)}` : null
  };
}

function isMember(roomId, userId) {
  return db.prepare('SELECT * FROM room_members WHERE room_id=? AND user_id=?').get(roomId, userId);
}

// ---------------------------------------------------------------------------
// Multer (uploads are already-encrypted bytes from the browser; we never
// look inside them)
// ---------------------------------------------------------------------------
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: AVATAR_DIR,
    filename: (req, file, cb) => cb(null, `${req.userId}-${Date.now()}${path.extname(file.originalname) || '.bin'}`)
  }),
  limits: { fileSize: 8 * 1024 * 1024 }
});

const fileUpload = multer({
  storage: multer.diskStorage({
    destination: FILES_DIR,
    filename: (req, file, cb) => cb(null, `${uuid()}.enc`)
  }),
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB ciphertext cap (covers video/voice notes)
});

// ============================================================================
// AUTH ROUTES — username + password only, no phone/email
// ============================================================================

// Create account. Client has already generated an RSA-OAEP keypair and
// encrypted the private key with a key derived from the password (PBKDF2).
// The server only ever sees: name, username, bcrypt-hashed password, the
// PUBLIC key, and the ENCRYPTED private key blob (useless without password).
app.post('/api/signup', (req, res) => {
  const { name, username, password, publicKey, encryptedPrivateKey, pkSalt, pkIv } = req.body || {};
  if (!name || !username || !password || !publicKey || !encryptedPrivateKey || !pkSalt || !pkIv) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const uname = String(username).trim().toLowerCase();
  if (!/^[a-z0-9_.]{3,20}$/.test(uname)) {
    return res.status(400).json({ error: 'Username must be 3-20 chars: letters, numbers, _ or .' });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username=?').get(uname);
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const id = uuid();
  const password_hash = bcrypt.hashSync(password, 10);
  db.prepare(`INSERT INTO users (id,name,username,password_hash,public_key,encrypted_private_key,pk_salt,pk_iv,avatar_path,created_at)
              VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(id, name.trim(), uname, password_hash, publicKey, encryptedPrivateKey, pkSalt, pkIv, null, Date.now());

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
});

// Login — only accounts created above can log in.
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
  const uname = String(username).trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(uname);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = signToken(user);
  res.json({
    token,
    user: publicUser(user),
    // sent so the client can locally decrypt the private key using the password
    keyBundle: { encryptedPrivateKey: user.encrypted_private_key, pkSalt: user.pk_salt, pkIv: user.pk_iv }
  });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({
    user: publicUser(user),
    keyBundle: { encryptedPrivateKey: user.encrypted_private_key, pkSalt: user.pk_salt, pkIv: user.pk_iv }
  });
});

app.put('/api/profile', authMiddleware, (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  db.prepare('UPDATE users SET name=? WHERE id=?').run(name.trim(), req.userId);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.userId);
  res.json({ user: publicUser(user) });
});

app.post('/api/profile/avatar', authMiddleware, avatarUpload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.userId);
  if (user.avatar_path) {
    const old = path.join(AVATAR_DIR, path.basename(user.avatar_path));
    fs.existsSync(old) && fs.unlinkSync(old);
  }
  db.prepare('UPDATE users SET avatar_path=? WHERE id=?').run(req.file.filename, req.userId);
  const updated = db.prepare('SELECT * FROM users WHERE id=?').get(req.userId);
  res.json({ user: publicUser(updated) });
});

// Find users by username (to start a DM or add to a group), and look up public keys.
app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  if (!q) return res.json({ users: [] });
  const rows = db.prepare('SELECT * FROM users WHERE username LIKE ? AND id != ? LIMIT 20')
    .all(`%${q}%`, req.userId);
  res.json({ users: rows.map(publicUser) });
});

app.get('/api/users/:id', authMiddleware, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ user: publicUser(u) });
});

// ============================================================================
// ROOM ROUTES — DMs, groups, channels (unified: each room has one AES key,
// wrapped per-member with that member's RSA public key)
// ============================================================================

// Create a room. Client supplies the room's AES key already wrapped
// (RSA-OAEP) for every initial member, since only the client can encrypt
// for another user's public key correctly (using keys fetched from /api/users).
app.post('/api/rooms', authMiddleware, (req, res) => {
  const { type, name, isPublic, members } = req.body || {};
  // members: [{ userId, encryptedKey, iv, role }]
  if (!['dm', 'group', 'channel'].includes(type)) return res.status(400).json({ error: 'Invalid room type' });
  if (!Array.isArray(members) || members.length === 0) return res.status(400).json({ error: 'Members required' });
  if (type !== 'dm' && (!name || !name.trim())) return res.status(400).json({ error: 'Name required for groups/channels' });

  const selfIncluded = members.some(m => m.userId === req.userId);
  if (!selfIncluded) return res.status(400).json({ error: 'Creator must be included in members' });

  const id = uuid();
  const now = Date.now();
  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO rooms (id,type,name,avatar_path,is_public,created_by,created_at) VALUES (?,?,?,?,?,?,?)`)
      .run(id, type, type === 'dm' ? null : name.trim(), null, isPublic ? 1 : 0, req.userId, now);
    const insertMember = db.prepare(`INSERT INTO room_members (room_id,user_id,role,encrypted_room_key,key_iv,joined_at)
                                      VALUES (?,?,?,?,?,?)`);
    for (const m of members) {
      const role = m.userId === req.userId ? 'admin' : (m.role === 'admin' ? 'admin' : 'member');
      insertMember.run(id, m.userId, role, m.encryptedKey, m.iv, now);
    }
  });
  tx();

  const room = db.prepare('SELECT * FROM rooms WHERE id=?').get(id);
  for (const m of members) io.to(`user_${m.userId}`).emit('room-created', { room: roomSummary(room, req.userId) });
  for (const m of members) socketJoinRoom(m.userId, id);
  res.json({ room: roomSummary(room, req.userId) });
});

function roomSummary(room, viewerId) {
  const memberCount = db.prepare('SELECT COUNT(*) c FROM room_members WHERE room_id=?').get(room.id).c;
  const mine = isMember(room.id, viewerId);
  return {
    id: room.id,
    type: room.type,
    name: room.name,
    isPublic: !!room.is_public,
    avatarUrl: room.avatar_path ? `/uploads/avatars/${path.basename(room.avatar_path)}` : null,
    createdBy: room.created_by,
    memberCount,
    myRole: mine ? mine.role : null,
    hasKey: mine ? !!mine.encrypted_room_key : false
  };
}

app.get('/api/rooms', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT r.* FROM rooms r
    JOIN room_members rm ON rm.room_id = r.id
    WHERE rm.user_id = ?
    ORDER BY r.created_at DESC
  `).all(req.userId);
  res.json({ rooms: rows.map(r => roomSummary(r, req.userId)) });
});

app.get('/api/rooms/discover', authMiddleware, (req, res) => {
  const rows = db.prepare(`SELECT * FROM rooms WHERE is_public=1 AND type IN ('group','channel') ORDER BY created_at DESC LIMIT 50`).all();
  const notMine = rows.filter(r => !isMember(r.id, req.userId));
  res.json({ rooms: notMine.map(r => roomSummary(r, req.userId)) });
});

app.get('/api/rooms/dm/:userId', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT r.* FROM rooms r
    JOIN room_members rm1 ON rm1.room_id=r.id AND rm1.user_id=?
    JOIN room_members rm2 ON rm2.room_id=r.id AND rm2.user_id=?
    WHERE r.type='dm'
  `).all(req.userId, req.params.userId);
  res.json({ room: rows[0] ? roomSummary(rows[0], req.userId) : null });
});

app.get('/api/rooms/:id/members', authMiddleware, (req, res) => {
  if (!isMember(req.params.id, req.userId)) return res.status(403).json({ error: 'Not a member' });
  const rows = db.prepare(`
    SELECT u.id, u.name, u.username, u.avatar_path, rm.role, rm.encrypted_room_key
    FROM room_members rm JOIN users u ON u.id = rm.user_id
    WHERE rm.room_id = ?
  `).all(req.params.id);
  res.json({
    members: rows.map(r => ({
      id: r.id, name: r.name, username: r.username, role: r.role,
      avatarUrl: r.avatar_path ? `/uploads/avatars/${path.basename(r.avatar_path)}` : null,
      hasKey: !!r.encrypted_room_key
    }))
  });
});

// Join a public group/channel (key starts NULL — "pending" until an online
// member with the room key wraps it for this user's public key)
app.post('/api/rooms/:id/join', authMiddleware, (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE id=?').get(req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (!room.is_public) return res.status(403).json({ error: 'This room is not public' });
  if (isMember(room.id, req.userId)) return res.status(409).json({ error: 'Already a member' });

  db.prepare(`INSERT INTO room_members (room_id,user_id,role,encrypted_room_key,key_iv,joined_at) VALUES (?,?,?,?,?,?)`)
    .run(room.id, req.userId, 'member', null, null, Date.now());

  socketJoinRoom(req.userId, room.id);
  io.to(`room_${room.id}`).emit('key-needed', { roomId: room.id, userId: req.userId });
  res.json({ room: roomSummary(room, req.userId) });
});

app.get('/api/rooms/:id/pending-keys', authMiddleware, (req, res) => {
  if (!isMember(req.params.id, req.userId)) return res.status(403).json({ error: 'Not a member' });
  const rows = db.prepare(`
    SELECT u.id, u.public_key FROM room_members rm JOIN users u ON u.id = rm.user_id
    WHERE rm.room_id = ? AND rm.encrypted_room_key IS NULL
  `).all(req.params.id);
  res.json({ pending: rows });
});

app.post('/api/rooms/:id/share-key', authMiddleware, (req, res) => {
  if (!isMember(req.params.id, req.userId)) return res.status(403).json({ error: 'Not a member' });
  const { targetUserId, encryptedKey, iv } = req.body || {};
  if (!targetUserId || !encryptedKey || !iv) return res.status(400).json({ error: 'Missing fields' });
  const target = isMember(req.params.id, targetUserId);
  if (!target) return res.status(404).json({ error: 'Target is not a member' });
  db.prepare('UPDATE room_members SET encrypted_room_key=?, key_iv=? WHERE room_id=? AND user_id=?')
    .run(encryptedKey, iv, req.params.id, targetUserId);
  io.to(`user_${targetUserId}`).emit('key-received', { roomId: req.params.id });
  res.json({ ok: true });
});

app.get('/api/rooms/:id/my-key', authMiddleware, (req, res) => {
  const m = isMember(req.params.id, req.userId);
  if (!m) return res.status(403).json({ error: 'Not a member' });
  res.json({ encryptedKey: m.encrypted_room_key, iv: m.key_iv });
});

// ============================================================================
// MESSAGES — text comes over the socket; files/voice notes come via this
// REST upload (already encrypted client-side), then get broadcast.
// ============================================================================

function canPost(roomId, userId) {
  const m = isMember(roomId, userId);
  if (!m) return false;
  const room = db.prepare('SELECT * FROM rooms WHERE id=?').get(roomId);
  if (room.type === 'channel') return m.role === 'admin'; // channels: admins broadcast, others read
  return true; // dm + group: anyone can post
}

app.get('/api/rooms/:id/messages', authMiddleware, (req, res) => {
  if (!isMember(req.params.id, req.userId)) return res.status(403).json({ error: 'Not a member' });
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const before = parseInt(req.query.before) || Date.now() + 1;
  const rows = db.prepare(`
    SELECT * FROM messages WHERE room_id=? AND created_at < ? ORDER BY created_at DESC LIMIT ?
  `).all(req.params.id, before, limit);
  res.json({ messages: rows.reverse().map(messageOut) });
});

function messageOut(m) {
  return {
    id: m.id, roomId: m.room_id, senderId: m.sender_id, type: m.type,
    ciphertext: m.ciphertext, iv: m.iv,
    fileUrl: m.file_path ? `/api/files/${m.id}` : null,
    fileSize: m.file_size, createdAt: m.created_at
  };
}

app.post('/api/upload', authMiddleware, fileUpload.single('file'), (req, res) => {
  const { roomId, type, ciphertext, iv } = req.body || {};
  if (!req.file || !roomId || !type || !ciphertext || !iv) return res.status(400).json({ error: 'Missing fields' });
  if (!['image', 'video', 'audio', 'pdf'].includes(type)) return res.status(400).json({ error: 'Invalid type' });
  if (!canPost(roomId, req.userId)) return res.status(403).json({ error: 'Not allowed to post in this room' });

  const id = uuid();
  const now = Date.now();
  db.prepare(`INSERT INTO messages (id,room_id,sender_id,type,ciphertext,iv,file_path,file_size,created_at)
              VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(id, roomId, req.userId, type, ciphertext, iv, req.file.filename, req.file.size, now);

  const msg = messageOut(db.prepare('SELECT * FROM messages WHERE id=?').get(id));
  io.to(`room_${roomId}`).emit('new-message', msg);
  res.json({ message: msg });
});

app.get('/api/files/:messageId', authMiddleware, (req, res) => {
  const m = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.messageId);
  if (!m || !m.file_path) return res.status(404).end();
  if (!isMember(m.room_id, req.userId)) return res.status(403).end();
  res.sendFile(path.join(FILES_DIR, m.file_path));
});

// ============================================================================
// SOCKET.IO — auth + realtime text message relay
// ============================================================================

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.uid;
    next();
  } catch (e) {
    next(new Error('unauthorized'));
  }
});

function socketJoinRoom(userId, roomId) {
  for (const [, s] of io.sockets.sockets) {
    if (s.userId === userId) s.join(`room_${roomId}`);
  }
}

io.on('connection', (socket) => {
  socket.join(`user_${socket.userId}`);
  const rooms = db.prepare('SELECT room_id FROM room_members WHERE user_id=?').all(socket.userId);
  for (const r of rooms) socket.join(`room_${r.room_id}`);

  socket.on('send-message', (payload, ack) => {
    try {
      const { roomId, ciphertext, iv } = payload || {};
      if (!roomId || !ciphertext || !iv) return ack && ack({ error: 'Missing fields' });
      if (!canPost(roomId, socket.userId)) return ack && ack({ error: 'Not allowed to post in this room' });
      const id = uuid();
      const now = Date.now();
      db.prepare(`INSERT INTO messages (id,room_id,sender_id,type,ciphertext,iv,file_path,file_size,created_at)
                  VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(id, roomId, socket.userId, 'text', ciphertext, iv, null, null, now);
      const msg = messageOut(db.prepare('SELECT * FROM messages WHERE id=?').get(id));
      io.to(`room_${roomId}`).emit('new-message', msg);
      ack && ack({ message: msg });
    } catch (e) {
      ack && ack({ error: 'Server error' });
    }
  });

  socket.on('typing', ({ roomId }) => {
    if (roomId) socket.to(`room_${roomId}`).emit('typing', { roomId, userId: socket.userId });
  });
});

// ---------------------------------------------------------------------------
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => console.log(`PlexxoTalk server running on port ${PORT}`));
