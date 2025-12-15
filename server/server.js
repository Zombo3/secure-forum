import express from 'express';
import cookieParser from 'cookie-parser';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';
import { engine } from 'express-handlebars';
import crypto from 'crypto';
import 'dotenv/config';
import nodemailer from 'nodemailer';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';

import argon2 from 'argon2';
import './db/db.js';
import { dbGet, dbRun, dbAll } from './db/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: true,
    credentials: true
  }
});
const PORT = process.env.PORT || 3000;

io.use(async (socket, next) => {
  try {
    const cookieHeader = socket.handshake.headers.cookie || '';
    const sid = getCookieValue(cookieHeader, 'sessionId');

    if (!sid) return next(new Error('Authentication required'));

    const now = Date.now();
    const row = await dbGet(
      `SELECT u.id, u.username, u.display_name
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.session_id = ?
       LIMIT 1`,
      [sid]
    );

    if (!row) return next(new Error('Authentication required'));

    const sess = await dbGet(
      `SELECT expires_at FROM sessions WHERE session_id = ? LIMIT 1`,
      [sid]
    );

    if (!sess || sess.expires_at < now) return next(new Error('Authentication required'));

    // Attach user info to socket (like socket.request.session in the textbook)
    socket.user = {
      id: row.id,
      username: row.username,
      display_name: row.display_name
    };

    return next();
  } catch (err) {
    console.error('Socket auth error:', err);
    return next(new Error('Authentication required'));
  }
});

// Behind nginx / reverse proxy
app.set('trust proxy', 1);

// =====================
// DB-backed sessions (required)
// =====================
const SESSION_TTL_MS = 1000 * 60 * 60; // 1 hour

async function initSessionsTable() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await dbRun(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`);
}

let lastCleanup = 0;
async function cleanupExpiredSessionsIfNeeded() {
  const now = Date.now();
  if (now - lastCleanup < 5 * 60 * 1000) return; // once per 5 minutes max
  lastCleanup = now;
  await dbRun(`DELETE FROM sessions WHERE expires_at < ?`, [now]);
}

async function getCurrentUser(req) {
  const sid = req.cookies?.sessionId;
  if (!sid) return null;

  const now = Date.now();

  const row = await dbGet(
    `SELECT u.id, u.username, u.display_name, u.name_color, u.avatar, s.expires_at
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.session_id = ?
     LIMIT 1`,
    [sid]
  );

  if (!row) return null;

  if (row.expires_at < now) {
    await dbRun(`DELETE FROM sessions WHERE session_id = ?`, [sid]);
    return null;
  }

  await dbRun(`UPDATE sessions SET last_seen = ? WHERE session_id = ?`, [now, sid]);

  return {
    id: row.id,
    username: row.username,
    display_name: row.display_name,
    name_color: row.name_color,
    avatar: row.avatar
  };
}

// Basic IP helper (works behind proxies if x-forwarded-for is set)
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '';
}

// =====================
// Handlebars setup
// =====================
app.engine(
  'hbs',
  engine({
    extname: 'hbs',
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views', 'layouts'),
    partialsDir: path.join(__dirname, 'views', 'partials'),
    helpers: {
      formatDate: (d) => new Date(d).toLocaleString(),
      eq: (a, b) => a === b
    }
  })
);

app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser()); // ✅ unsigned cookies (no extras)

app.use('/public', express.static(path.join(__dirname, 'public')));

// Static files are served by Nginx at /static/, so this route just reminds us:
app.get('/static/*', (req, res) =>
  res.status(404).send('Static is served by Nginx container')
);

// Make currentUser available to templates (DB-backed)
app.use(async (req, res, next) => {
  try {
    await cleanupExpiredSessionsIfNeeded();
    res.locals.currentUser = await getCurrentUser(req);
  } catch (err) {
    console.error('currentUser middleware error:', err);
    res.locals.currentUser = null;
  }
  next();
});

// =====================
// Helpers
// =====================
function getCookieValue(cookieHeader, name) {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(';').map((p) => p.trim());
  for (const p of parts) {
    if (p.startsWith(name + '=')) {
      return decodeURIComponent(p.slice(name.length + 1));
    }
  }
  return null;
}

function requireAuth(req, res, next) {
  if (!res.locals.currentUser) {
    return res.status(401).render('login', {
      title: 'Login',
      error: 'Please log in to access your profile.'
    });
  }
  next();
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidHexColor(color) {
  return /^#[0-9a-fA-F]{6}$/.test(String(color || '').trim());
}

function isStrongPassword(pw) {
  const s = String(pw || '');
  return (
    s.length >= 8 &&
    /[a-z]/.test(s) &&
    /[A-Z]/.test(s) &&
    /[0-9]/.test(s) &&
    /[^A-Za-z0-9]/.test(s)
  );
}

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },

  // Prevent “stuck loading” forever:
  connectionTimeout: 10_000, // 10s
  greetingTimeout: 10_000, // 10s
  socketTimeout: 10_000 // 10s
});

// =====================
// Routes
// =====================
io.on('connection', async (socket) => {
  console.log('Socket connected:', socket.id);
  console.log('Socket user:', socket.user);

  // Send recent chat history to the newly connected client
  if (!socket.user) return; // auth should set this; safety guard

  const HISTORY_LIMIT = 50;
  try {
    const rows = await dbAll(
      `
      SELECT display_name AS user,
             message AS text,
             created_at AS timestamp,
             room_id
      FROM chat_messages
      WHERE room_id = 1
      ORDER BY created_at DESC
      LIMIT ?
      `,
      [HISTORY_LIMIT]
    );

    // rows are newest->oldest; reverse so client renders oldest->newest
    socket.emit('chat:history', rows.reverse());
  } catch (err) {
    console.error('Failed to load chat history:', err);
  }

  socket.on('chat:send', async (data) => {
    try {
      console.log('CHAT: received chat:send from', socket.user, 'data=', data);

      if (!data || typeof data.text !== 'string') return;

      const text = data.text.trim();
      if (!text) return;

      const now = Date.now();

      // Persist message
      await dbRun(
        `INSERT INTO chat_messages (room_id, user_id, display_name, message, created_at)
         VALUES (1, ?, ?, ?, ?)`,
        [socket.user.id, socket.user.display_name, text, now]
      );

      // Broadcast to everyone
      io.emit('chat:message', {
        user: socket.user.display_name,
        text,
        timestamp: now
      });
    } catch (err) {
      console.error('chat send error:', err);
    }
  });

  socket.on('disconnect', () => {
    console.log('Socket disconnected:', socket.id);
  });
});

// Home
app.get('/', (req, res) => {
  res.render('home', { title: 'Insecure Forum' });
});

// Register (GET)
app.get('/register', (req, res) => {
  res.render('register', { title: 'Register' });
});

// Register (POST)
app.post('/register', async (req, res) => {
  try {
    const { username, password, email, display_name } = req.body;

    if (!username || !password || !email || !display_name) {
      return res.status(400).render('register', {
        title: 'Register',
        error: 'Username, password, email, and display name are required.'
      });
    }

    if (display_name.trim().toLowerCase() === username.trim().toLowerCase()) {
      return res.status(400).render('register', {
        title: 'Register',
        error: 'Display name must be different from username.'
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).render('register', {
        title: 'Register',
        error: 'Invalid email format.'
      });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).render('register', {
        title: 'Register',
        error:
          'Password must be at least 8 chars and include upper, lower, number, and symbol.'
      });
    }

    const existingUser = await dbGet('SELECT id FROM users WHERE username = ?', [
      username
    ]);
    if (existingUser) {
      return res.status(400).render('register', {
        title: 'Register',
        error: 'Username already taken.'
      });
    }

    const existingEmail = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existingEmail) {
      return res.status(400).render('register', {
        title: 'Register',
        error: 'Email already in use.'
      });
    }

    const password_hash = await argon2.hash(password);
    const now = Date.now();

    await dbRun(
      `INSERT INTO users (username, password_hash, email, display_name, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [username, password_hash, email, display_name, now, now]
    );

    return res.render('login', {
      title: 'Login',
      message: 'Account created. Please log in.'
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).render('register', {
      title: 'Register',
      error: 'Server error. Please try again.'
    });
  }
});

// Login (GET)
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' });
});

// Login (POST)
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = getClientIp(req);
    const now = Date.now();

    if (!username || !password) {
      return res.status(400).render('login', {
        title: 'Login',
        error: 'Username and password required.'
      });
    }

    const userRow = await dbGet(
      `SELECT id, username, password_hash, display_name, name_color, avatar,
              failed_attempts, locked_until
       FROM users
       WHERE username = ?`,
      [username]
    );

    if (userRow && userRow.locked_until && userRow.locked_until > now) {
      await dbRun(
        `INSERT INTO login_attempts (username, ip, ts, success)
         VALUES (?, ?, ?, ?)`,
        [username, ip, now, 0]
      );

      const unlockAt = new Date(userRow.locked_until).toLocaleString();
      return res.status(403).render('login', {
        title: 'Login',
        error: `Account locked due to failed attempts. Try again at ${unlockAt}.`
      });
    }

    if (!userRow) {
      await dbRun(
        `INSERT INTO login_attempts (username, ip, ts, success)
         VALUES (?, ?, ?, ?)`,
        [username, ip, now, 0]
      );

      return res.status(401).render('login', {
        title: 'Login',
        error: 'Invalid username or password.'
      });
    }

    const ok = await argon2.verify(userRow.password_hash, password);

    if (!ok) {
      await dbRun(
        `INSERT INTO login_attempts (username, ip, ts, success)
         VALUES (?, ?, ?, ?)`,
        [username, ip, now, 0]
      );

      const newAttempts = (userRow.failed_attempts || 0) + 1;
      const MAX_ATTEMPTS = 5;
      const LOCK_MINUTES = 15;

      if (newAttempts >= MAX_ATTEMPTS) {
        const lockedUntil = now + LOCK_MINUTES * 60 * 1000;

        await dbRun(
          `UPDATE users
           SET failed_attempts = ?, locked_until = ?, updated_at = ?
           WHERE id = ?`,
          [newAttempts, lockedUntil, now, userRow.id]
        );

        const unlockAt = new Date(lockedUntil).toLocaleString();
        return res.status(403).render('login', {
          title: 'Login',
          error: `Too many failed attempts. Account locked until ${unlockAt}.`
        });
      }

      await dbRun(
        `UPDATE users
         SET failed_attempts = ?, locked_until = NULL, updated_at = ?
         WHERE id = ?`,
        [newAttempts, now, userRow.id]
      );

      return res.status(401).render('login', {
        title: 'Login',
        error: `Invalid username or password. Attempts: ${newAttempts}/5`
      });
    }

    await dbRun(
      `INSERT INTO login_attempts (username, ip, ts, success)
       VALUES (?, ?, ?, ?)`,
      [username, ip, now, 1]
    );

    await dbRun(
      `UPDATE users
       SET failed_attempts = 0, locked_until = NULL, updated_at = ?
       WHERE id = ?`,
      [now, userRow.id]
    );

    // Create DB session (required)
    const sessionId = uuidv4();
    const expiresAtMs = now + SESSION_TTL_MS;

    await dbRun(
      `INSERT INTO sessions (session_id, user_id, expires_at, created_at, last_seen)
       VALUES (?, ?, ?, ?, ?)`,
      [sessionId, userRow.id, expiresAtMs, now, now]
    );

    res.cookie('sessionId', sessionId, {
      expires: new Date(expiresAtMs),
      httpOnly: true,
      sameSite: 'lax'
      // secure: true should be set if you are strictly HTTPS in production
    });

    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).render('login', {
      title: 'Login',
      error: 'Server error. Please try again.'
    });
  }
});

// Logout (POST)
app.post('/logout', async (req, res) => {
  try {
    const sid = req.cookies?.sessionId;
    if (sid) await dbRun(`DELETE FROM sessions WHERE session_id = ?`, [sid]);
  } catch (err) {
    console.error('Logout error:', err);
  }
  res.clearCookie('sessionId');
  res.redirect('/');
});

/* ============================
   PASSWORD RECOVERY (Step 1)
============================ */

// Forgot password (GET)
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { title: 'Forgot Password' });
});

// Forgot password (POST) - create token in DB and show "sent" message
app.post('/forgot-password', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const now = Date.now();

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!emailOk) {
      return res.status(400).render('forgot-password', {
        title: 'Forgot Password',
        error: 'Invalid email format.'
      });
    }

    const message = 'If the email exists, we sent a reset link.';

    const user = await dbGet(`SELECT id FROM users WHERE email = ?`, [email]);
    if (!user) {
      return res.render('forgot-password', { title: 'Forgot Password', message });
    }

    // Create raw token (goes in link) + store hash in DB
    const token = crypto.randomBytes(32).toString('hex');
    const token_hash = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = now + 30 * 60 * 1000; // 30 minutes

    await dbRun(
      `INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at)
       VALUES (?, ?, ?, 0, ?)`,
      [user.id, token_hash, expiresAt, now]
    );

    const resetLink = `${process.env.APP_BASE_URL}/reset-password?token=${token}`;
    console.log('MAIL: sending reset email to:', email);

    await mailer.sendMail({
      from: process.env.SMTP_FROM,
      to: email,
      subject: 'Password Reset - Less Wild West Forum',
      text: `You requested a password reset.\n\nReset your password using this link:\n${resetLink}\n\nIf you did not request this, ignore this email.`
    });
    console.log('MAIL: sendMail finished');

    return res.render('forgot-password', { title: 'Forgot Password', message });
  } catch (err) {
    console.error('forgot-password error:', err);
    return res.status(500).render('forgot-password', {
      title: 'Forgot Password',
      error: 'Server error. Please try again.'
    });
  }
});

// Reset password (GET)
app.get('/reset-password', async (req, res) => {
  try {
    const token = String(req.query.token || '').trim();
    const now = Date.now();

    if (!token) {
      return res.status(400).render('reset-password', {
        title: 'Reset Password',
        error: 'Missing token.'
      });
    }

    console.log('RESET DEBUG token:', token);

    const token_hash = crypto.createHash('sha256').update(token).digest('hex');
    console.log('RESET DEBUG token_hash:', token_hash);

    const row = await dbGet(
      `SELECT user_id, expires_at, used
       FROM password_resets
       WHERE token_hash = ?
       LIMIT 1`,
      [token_hash]
    );

    console.log('RESET DEBUG row:', row);
    console.log('RESET DEBUG now:', now);

    if (!row || row.used !== 0 || row.expires_at < now) {
      return res.status(400).render('reset-password', {
        title: 'Reset Password',
        error: 'Invalid or expired reset link.'
      });
    }

    return res.render('reset-password', { title: 'Reset Password', token });
  } catch (err) {
    console.error('reset-password GET error:', err);
    return res.status(500).render('reset-password', {
      title: 'Reset Password',
      error: 'Server error. Please try again.'
    });
  }
});

// Reset password (POST)
app.post('/reset-password', async (req, res) => {
  try {
    const token = String(req.body.token || '').trim();
    const new_password = String(req.body.new_password || '');
    const confirm_password = String(req.body.confirm_password || '');
    const now = Date.now();

    if (!token) {
      return res.status(400).render('reset-password', {
        title: 'Reset Password',
        error: 'Missing token.'
      });
    }

    if (!new_password || new_password !== confirm_password) {
      return res.status(400).render('reset-password', {
        title: 'Reset Password',
        token,
        error: 'Passwords do not match.'
      });
    }

    // same strength rules you already use elsewhere
    const strong =
      new_password.length >= 8 &&
      /[a-z]/.test(new_password) &&
      /[A-Z]/.test(new_password) &&
      /[0-9]/.test(new_password) &&
      /[^A-Za-z0-9]/.test(new_password);

    if (!strong) {
      return res.status(400).render('reset-password', {
        title: 'Reset Password',
        token,
        error:
          'Password must be at least 8 chars and include upper, lower, number, and symbol.'
      });
    }

    const token_hash = crypto.createHash('sha256').update(token).digest('hex');

    const row = await dbGet(
      `SELECT id, user_id, expires_at, used
       FROM password_resets
       WHERE token_hash = ?
       LIMIT 1`,
      [token_hash]
    );

    if (!row || row.used !== 0 || row.expires_at < now) {
      return res.status(400).render('reset-password', {
        title: 'Reset Password',
        error: 'Invalid or expired reset link.'
      });
    }

    // Mark token as used first (prevents reuse even if something crashes later)
    await dbRun(`UPDATE password_resets SET used = 1 WHERE id = ?`, [row.id]);

    // Set new password
    const newHash = await argon2.hash(new_password);
    await dbRun(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, [
      newHash,
      now,
      row.user_id
    ]);

    // Invalidate all sessions for this user (required)
    await dbRun(`DELETE FROM sessions WHERE user_id = ?`, [row.user_id]);

    // Clear cookie too
    res.clearCookie('sessionId');

    return res.render('login', {
      title: 'Login',
      message: 'Password reset successful. Please log in.'
    });
  } catch (err) {
    console.error('reset-password POST error:', err);
    return res.status(500).render('reset-password', {
      title: 'Reset Password',
      error: 'Server error. Please try again.'
    });
  }
});

/* ============================
   PROFILE ROUTES (Required)
============================ */

// GET profile (renders page)
app.get('/profile', requireAuth, async (req, res) => {
  const userId = res.locals.currentUser.id;

  const user = await dbGet(
    `SELECT username, email, display_name, name_color, avatar, bio
     FROM users
     WHERE id = ?`,
    [userId]
  );

  if (!user) return res.status(404).send('User not found');

  res.render('profile', {
    title: 'Your Profile',
    user
  });
});

// Change display name (and update existing comments)
app.post('/profile/display-name', requireAuth, async (req, res) => {
  const userId = res.locals.currentUser.id;
  const display_name = String(req.body.display_name || '').trim();

  if (!display_name || display_name.length < 2 || display_name.length > 32) {
    return res.status(400).send('Invalid display name');
  }

  const now = Date.now();

  try {
    await dbRun(
      `UPDATE users
       SET display_name = ?, updated_at = ?
       WHERE id = ?`,
      [display_name, now, userId]
    );

    // update old comments to reflect new display name
    await dbRun(
      `UPDATE comments
       SET display_name = ?
       WHERE user_id = ?`,
      [display_name, userId]
    );

    res.redirect('/profile');
  } catch (err) {
    return res.status(400).send('Display name already taken');
  }
});

// Profile customization: name_color + avatar + bio
app.post('/profile/customize', requireAuth, async (req, res) => {
  const userId = res.locals.currentUser.id;
  const name_color = String(req.body.name_color || '').trim();
  const avatar = String(req.body.avatar || '').trim();
  const bio = String(req.body.bio || '').trim();

  if (!isValidHexColor(name_color)) {
    return res.status(400).send('Invalid name color (must be #RRGGBB)');
  }

  if (avatar.length > 200) return res.status(400).send('Avatar too long');
  if (bio.length > 280) return res.status(400).send('Bio too long');

  const now = Date.now();

  await dbRun(
    `UPDATE users
     SET name_color = ?, avatar = ?, bio = ?, updated_at = ?
     WHERE id = ?`,
    [name_color, avatar, bio, now, userId]
  );

  res.redirect('/profile');
});

// Change email (verify password + validate + unique)
app.post('/profile/email', requireAuth, async (req, res) => {
  const userId = res.locals.currentUser.id;
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');

  if (!isValidEmail(email)) {
    return res.status(400).send('Invalid email format');
  }

  const userRow = await dbGet(`SELECT password_hash FROM users WHERE id = ?`, [
    userId
  ]);
  if (!userRow) return res.status(404).send('User not found');

  const ok = await argon2.verify(userRow.password_hash, password);
  if (!ok) return res.status(403).send('Password incorrect');

  const existingEmail = await dbGet(`SELECT id FROM users WHERE email = ?`, [email]);
  if (existingEmail && existingEmail.id !== userId) {
    return res.status(400).send('Email already in use');
  }

  const now = Date.now();
  await dbRun(
    `UPDATE users
     SET email = ?, updated_at = ?
     WHERE id = ?`,
    [email, now, userId]
  );

  res.redirect('/profile');
});

// Change password (verify current password + strength + invalidate sessions)
app.post('/profile/password', requireAuth, async (req, res) => {
  const userId = res.locals.currentUser.id;
  const current_password = String(req.body.current_password || '');
  const new_password = String(req.body.new_password || '');
  const confirm_password = String(req.body.confirm_password || '');

  if (!new_password || new_password !== confirm_password) {
    return res.status(400).send('New passwords do not match');
  }

  if (!isStrongPassword(new_password)) {
    return res.status(400).send(
      'Password must be at least 8 chars and include upper, lower, number, and symbol.'
    );
  }

  const row = await dbGet(`SELECT password_hash FROM users WHERE id = ?`, [userId]);
  if (!row) return res.status(404).send('User not found');

  const ok = await argon2.verify(row.password_hash, current_password);
  if (!ok) return res.status(403).send('Current password incorrect');

  const newHash = await argon2.hash(new_password);
  const now = Date.now();

  await dbRun(
    `UPDATE users
     SET password_hash = ?, updated_at = ?
     WHERE id = ?`,
    [newHash, now, userId]
  );

  // invalidate all sessions
  await dbRun(`DELETE FROM sessions WHERE user_id = ?`, [userId]);

  res.clearCookie('sessionId');
  res.redirect('/login');
});

// Comments feed (GET) -> SQLite + Pagination
app.get('/comments', async (req, res) => {
  try {
    const perPage = 20;

    let page = parseInt(req.query.page || '1', 10);
    if (Number.isNaN(page) || page < 1) page = 1;

    const countRow = await dbGet('SELECT COUNT(*) AS total FROM comments');
    const totalComments = countRow ? countRow.total : 0;

    const totalPages = Math.max(1, Math.ceil(totalComments / perPage));
    if (page > totalPages) page = totalPages;

    const offset = (page - 1) * perPage;

    const rows = await dbAll(
      `SELECT id,
              display_name AS author,
              text,
              created_at AS createdAt
       FROM comments
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [perPage, offset]
    );

    res.render('comments', {
      title: 'All Comments',
      comments: rows,
      pagination: {
        page,
        perPage,
        totalComments,
        totalPages,
        hasPrev: page > 1,
        hasNext: page < totalPages,
        prevPage: page > 1 ? page - 1 : 1,
        nextPage: page < totalPages ? page + 1 : totalPages
      }
    });
  } catch (err) {
    console.error('Load comments error:', err);
    res.status(500).send('Server error');
  }
});

// New comment form (GET)
app.get('/comment/new', async (req, res) => {
  const user = await getCurrentUser(req);
  if (!user) {
    return res
      .status(401)
      .render('login', { title: 'Login', error: 'Please log in to post a comment.' });
  }
  res.render('new-comment', { title: 'New Comment' });
});

// Create comment (POST)
app.post('/comment', async (req, res) => {
  try {
    const user = await getCurrentUser(req);
    if (!user) {
      return res
        .status(401)
        .render('login', { title: 'Login', error: 'You must be logged in to comment.' });
    }

    const { text } = req.body;
    if (!text || text.trim() === '') {
      return res
        .status(400)
        .render('new-comment', { title: 'New Comment', error: 'Comment text is required.' });
    }

    const now = Date.now();
    await dbRun(
      `INSERT INTO comments (user_id, display_name, text, created_at)
       VALUES (?, ?, ?, ?)`,
      [user.id, user.display_name, text, now]
    );

    res.redirect('/comments');
  } catch (err) {
    console.error('Create comment error:', err);
    res.status(500).send('Server error');
  }
});
// Delete comment (POST) - only allow deleting your own comment
app.post('/comment/:id/delete', async (req, res) => {
  try {
    const user = await getCurrentUser(req);
    if (!user) {
      return res
        .status(401)
        .render('login', { title: 'Login', error: 'Please log in to manage comments.' });
    }

    const commentId = parseInt(req.params.id, 10);
    if (Number.isNaN(commentId)) return res.status(400).send('Invalid comment id');

    const row = await dbGet(`SELECT user_id FROM comments WHERE id = ?`, [commentId]);
    if (!row) return res.status(404).send('Comment not found');

    if (row.user_id !== user.id) {
      return res.status(403).send('You can only delete your own comments');
    }

    await dbRun(`DELETE FROM comments WHERE id = ?`, [commentId]);

    res.redirect('/comments');
  } catch (err) {
    console.error('Delete comment error:', err);
    res.status(500).send('Server error');
  }
});


// Start server after DB init
(async () => {
  try {
    await initSessionsTable();
    server.listen(PORT, () => {
      console.log(`Insecure Forum running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Fatal init error:', err);
    process.exit(1);
  }
})();
