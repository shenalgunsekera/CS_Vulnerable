/**
 * =============================================================
 * CFGS - Colombo Fort Group Services PVT LTD
 * Ticket System Backend - VULNERABLE VERSION
 * Port: 3000
 *
 * ⚠️  THIS IS INTENTIONALLY INSECURE FOR EDUCATIONAL PURPOSES ⚠️
 * DO NOT USE IN PRODUCTION
 *
 * VULNERABILITIES DEMONSTRATED:
 *  (A) Session Hijacking    - cookies readable by JS, no timeout,
 *                             no session regeneration
 *  (B) Privilege Escalation - no backend role enforcement
 *  (C) SQL Injection        - raw string concatenation in queries,
 *                             UNION attack extracts all user passwords
 *                             *** NOW USES REAL SQLite DATABASE ***
 *  (D) Ping of Death        - /api/ping endpoint has no payload size limit,
 *                             oversized packets exhaust memory and crash the process
 *  (E) MMCC Backdoor        - Unauthenticated Multimedia Conference Control
 *                             service on port 5050, exposes sensitive info
 * =============================================================
 */

const express        = require('express');
const session        = require('express-session');
const path           = require('path');
const net            = require('net');
const Database       = require('better-sqlite3');

const app       = express();
const PORT      = 3000;
const MMCC_PORT = 5050;

// ── Real SQLite Database Setup ──────────────────────────────
// VULNERABILITY (C): Uses a real SQLite database with raw string
// concatenation in queries — real SQL injection is possible!

const db = new Database('./cfgs_vulnerable.db');

// Create tables and seed data on startup
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL,
    name     TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS tickets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',
    priority      TEXT NOT NULL DEFAULT 'medium',
    createdBy     INTEGER NOT NULL,
    createdByName TEXT NOT NULL,
    createdAt     TEXT NOT NULL
  );
`);

// Seed users if empty — VULNERABILITY: passwords stored in plaintext
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
if (userCount === 0) {
  const insertUser = db.prepare(
    'INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)'
  );
  insertUser.run('admin',     'admin123',   'admin',    'Admin User');
  insertUser.run('manager1',  'manager123', 'manager',  'John Manager');
  insertUser.run('employee1', 'emp123',     'employee', 'Alice Employee');
  insertUser.run('employee2', 'emp456',     'employee', 'Bob Employee');
}

// Seed tickets if empty
const ticketCount = db.prepare('SELECT COUNT(*) as c FROM tickets').get().c;
if (ticketCount === 0) {
  const insertTicket = db.prepare(
    'INSERT INTO tickets (title, description, status, priority, createdBy, createdByName, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  insertTicket.run('Network Issue in 3rd Floor', 'WiFi drops every hour on the 3rd floor.',  'open',   'high',   3, 'Alice Employee', new Date(Date.now() - 86400000).toISOString());
  insertTicket.run('Printer Not Working',         'HP printer in accounts dept is offline.',  'open',   'medium', 4, 'Bob Employee',   new Date(Date.now() - 43200000).toISOString());
  insertTicket.run('Software License Renewal',    'Adobe CC license expires next week.',      'closed', 'low',    3, 'Alice Employee', new Date(Date.now() - 172800000).toISOString());
}

console.log('  📦  SQLite database ready: cfgs_vulnerable.db');

// ── Middleware ──────────────────────────────────────────────
// VULNERABILITY (D): express.raw() with NO size limit
app.use('/api/ping', express.raw({ type: '*/*', limit: Infinity }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/**
 * VULNERABILITY (A): Insecure session configuration
 *  - httpOnly: false  → JS can read document.cookie
 *  - secure: false    → works over plain HTTP
 *  - No maxAge        → session never expires
 *  - No sameSite      → CSRF risk
 *  - Weak secret
 */
app.use(session({
  secret:            'cfgs-weak-secret-123',
  resave:            true,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,
    secure:   false,
  }
}));

// ── Helper ──────────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated. Please log in.' });
  }
  next();
}

// ── AUTH ROUTES ─────────────────────────────────────────────

/**
 * POST /api/login
 * VULNERABILITY (A): Session NOT regenerated after login
 */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: Plain comparison, no rate limiting
  const user = db.prepare(
    'SELECT * FROM users WHERE username = ? AND password = ?'
  ).get(username, password);

  if (!user) {
    return res.json({ success: false, message: 'Invalid username or password.' });
  }

  // VULNERABILITY: session.regenerate() NOT called
  req.session.user = {
    id:       user.id,
    username: user.username,
    role:     user.role,
    name:     user.name,
  };

  res.json({ success: true, role: user.role, name: user.name });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// GET /api/me
app.get('/api/me', requireLogin, (req, res) => {
  res.json(req.session.user);
});

// ── TICKET ROUTES ───────────────────────────────────────────

// GET /api/tickets
app.get('/api/tickets', requireLogin, (req, res) => {
  const tickets = db.prepare('SELECT * FROM tickets').all();
  res.json(tickets);
});

// POST /api/tickets
app.post('/api/tickets', requireLogin, (req, res) => {
  const { title, description, priority } = req.body;

  if (!title || !description) {
    return res.json({ success: false, message: 'Title and description are required.' });
  }

  const result = db.prepare(
    'INSERT INTO tickets (title, description, status, priority, createdBy, createdByName, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(
    title.trim(),
    description.trim(),
    'open',
    priority || 'medium',
    req.session.user.id,
    req.session.user.name,
    new Date().toISOString()
  );

  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(result.lastInsertRowid);
  res.json({ success: true, ticket });
});

/**
 * PUT /api/tickets/:id/close
 * VULNERABILITY (B): No role check — any logged-in user can close tickets
 * Attack: fetch('/api/tickets/1/close', { method:'PUT' })
 */
app.put('/api/tickets/:id/close', requireLogin, (req, res) => {
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(parseInt(req.params.id));

  if (!ticket) return res.json({ success: false, message: 'Ticket not found.' });
  if (ticket.status === 'closed') return res.json({ success: false, message: 'Already closed.' });

  db.prepare('UPDATE tickets SET status = ? WHERE id = ?').run('closed', ticket.id);
  res.json({ success: true });
});

/**
 * DELETE /api/tickets/:id
 * VULNERABILITY (B): No role check
 */
app.delete('/api/tickets/:id', requireLogin, (req, res) => {
  const id = parseInt(req.params.id);
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(id);

  if (!ticket) return res.json({ success: false, message: 'Ticket not found.' });

  db.prepare('DELETE FROM tickets WHERE id = ?').run(id);
  res.json({ success: true });
});

// ── ADMIN ROUTES ────────────────────────────────────────────

/**
 * GET /api/admin/users
 * VULNERABILITY (B): No role check — any logged-in user can access
 * Attack: fetch('/api/admin/users').then(r=>r.json()).then(console.log)
 */
app.get('/api/admin/users', requireLogin, (req, res) => {
  // VULNERABILITY: No admin check, and returns all users from real DB
  const users = db.prepare('SELECT id, username, role, name FROM users').all();
  res.json(users);
});

// ── SQL INJECTION (C) ────────────────────────────────────────

/**
 * GET /api/search?q=QUERY
 *
 * VULNERABILITY (C): REAL SQL Injection via string concatenation
 *
 * The search term is inserted DIRECTLY into the SQLite query string.
 * This is a REAL SQL injection against a real database.
 *
 * Normal use:  /api/search?q=wifi
 *
 * Attack (dump all passwords):
 *   /api/search?q=' UNION SELECT id,username,password,role,name,name,createdAt FROM users --
 *
 * Result: All usernames and plaintext passwords appear in search results!
 */
app.get('/api/search', requireLogin, (req, res) => {
  const q = req.query.q || '';

  // VULNERABILITY: User input directly concatenated into SQL query
  const rawQuery =
    `SELECT id, title, description, status, priority, createdByName, createdAt ` +
    `FROM tickets WHERE title LIKE '%${q}%' OR description LIKE '%${q}%'`;

  try {
    // VULNERABILITY: Raw query executed against real SQLite database
    const results = db.prepare(rawQuery).all();
    res.json({ success: true, results, rawQuery });
  } catch (e) {
    // Error message may reveal DB structure — another vulnerability
    res.json({ success: false, error: e.message, rawQuery });
  }
});

// ── PING OF DEATH (D) ────────────────────────────────────────

/**
 * POST /api/ping
 * VULNERABILITY (D): No payload size limit
 */
app.post('/api/ping', requireLogin, (req, res) => {
  const byteCount = req.body ? req.body.length : 0;

  res.json({
    success:   true,
    message:   'Pong!',
    bytesRead: byteCount,
    preview:   req.body ? req.body.slice(0, 64).toString('utf8') : '',
    warning:   'VULNERABILITY: server buffered the entire payload with no size check.',
  });
});

// ── MMCC SERVICE (E) — Port 5050 ────────────────────────────

/**
 * VULNERABILITY (E): Unauthenticated MMCC Service on Port 5050
 * No auth, no encryption — anyone can connect and extract info
 */
const mmccServer = net.createServer((socket) => {
  const clientAddr = socket.remoteAddress + ':' + socket.remotePort;
  console.log(`  [MMCC] Client connected: ${clientAddr}`);

  socket.write(
    '======================================\r\n' +
    '  CFGS Multimedia Conference Control  \r\n' +
    '  MMCC Service v1.0                   \r\n' +
    '  Colombo Fort Groups & Services      \r\n' +
    '======================================\r\n' +
    '\r\n' +
    'Welcome. Type HELP for available commands.\r\n' +
    '> '
  );

  socket.on('data', (data) => {
    const command = data.toString().trim().toUpperCase();
    console.log(`  [MMCC] Command from ${clientAddr}: ${command}`);

    switch (command) {
      case 'HELP':
        socket.write(
          'Available Commands:\r\n' +
          '  HELP     - Show this help menu\r\n' +
          '  INFO     - Show server information\r\n' +
          '  LIST     - List active conference sessions\r\n' +
          '  STATUS   - Show service status\r\n' +
          '  VERSION  - Show version information\r\n' +
          '  CONFIG   - Show service configuration\r\n' +
          '  QUIT     - Disconnect\r\n' +
          '> '
        );
        break;

      case 'INFO':
        // VULNERABILITY: Exposes DB file path and server info
        socket.write(
          'Server Information:\r\n' +
          '  Hostname : cfgs-server\r\n' +
          '  OS       : Windows/Linux\r\n' +
          '  Service  : MMCC v1.0\r\n' +
          `  Port     : ${MMCC_PORT}\r\n` +
          '  Web App  : http://localhost:3000\r\n' +
          '  DB Type  : SQLite\r\n' +
          '  DB File  : ./cfgs_vulnerable.db\r\n' +
          '  DB User  : (none - no auth)\r\n' +
          '> '
        );
        break;

      case 'LIST':
        socket.write(
          'Active Conference Sessions:\r\n' +
          '  Session #1 | User: admin      | Room: Board Meeting  | Status: Active\r\n' +
          '  Session #2 | User: manager1   | Room: IT Review      | Status: Active\r\n' +
          '  Session #3 | User: employee1  | Room: HR Meeting     | Status: Idle\r\n' +
          '> '
        );
        break;

      case 'STATUS':
        socket.write(
          'MMCC Service Status:\r\n' +
          '  Status   : RUNNING\r\n' +
          `  Port     : ${MMCC_PORT}\r\n` +
          '  Auth     : DISABLED\r\n' +
          '  Encrypt  : DISABLED\r\n' +
          '  Uptime   : 99 days\r\n' +
          '> '
        );
        break;

      case 'VERSION':
        socket.write(
          'MMCC Version Information:\r\n' +
          '  Version  : 1.0.0\r\n' +
          '  Build    : 2008-04-10\r\n' +
          '  Node.js  : ' + process.version + '\r\n' +
          '> '
        );
        break;

      case 'CONFIG':
        socket.write(
          'Service Configuration:\r\n' +
          '  max_connections : unlimited\r\n' +
          '  auth_required   : false\r\n' +
          '  encryption      : none\r\n' +
          '  log_level       : verbose\r\n' +
          '  db_file         : ./cfgs_vulnerable.db\r\n' +
          '  web_root        : ./public\r\n' +
          '> '
        );
        break;

      case 'QUIT':
        socket.write('Goodbye.\r\n');
        socket.end();
        break;

      default:
        socket.write(
          `Unknown command: ${command}\r\n` +
          'Type HELP for available commands.\r\n> '
        );
    }
  });

  socket.on('close', () => console.log(`  [MMCC] Client disconnected: ${clientAddr}`));
  socket.on('error', (err) => console.log(`  [MMCC] Socket error: ${err.message}`));
});

mmccServer.listen(MMCC_PORT, '0.0.0.0', () => {
  console.log(`  🎙️  MMCC Service running on port ${MMCC_PORT} (NO AUTH — VULNERABLE)`);
});

// ── START SERVER ────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ⚠️  CFGS TICKET SYSTEM — VULNERABLE VERSION');
  console.log('  ============================================');
  console.log(`  🌐  Running at: http://localhost:${PORT}`);
  console.log('');
  console.log('  Test Accounts:');
  console.log('  ┌─────────────┬─────────────┬──────────┐');
  console.log('  │ Username    │ Password    │ Role     │');
  console.log('  ├─────────────┼─────────────┼──────────┤');
  console.log('  │ admin       │ admin123    │ Admin    │');
  console.log('  │ manager1    │ manager123  │ Manager  │');
  console.log('  │ employee1   │ emp123      │ Employee │');
  console.log('  │ employee2   │ emp456      │ Employee │');
  console.log('  └─────────────┴─────────────┴──────────┘');
  console.log('');
  console.log('  Vulnerabilities:');
  console.log('  (A) Session Hijacking  — no timeout, JS-readable cookie');
  console.log('  (B) Privilege Escalation — no backend role enforcement');
  console.log('  (C) SQL Injection      — REAL SQLite DB, UNION attack dumps passwords');
  console.log('  (D) Ping of Death      — POST /api/ping, no size limit');
  console.log(`  (E) MMCC Backdoor      — port ${MMCC_PORT}, no auth required`);
  console.log('');
  console.log('  SQL Injection Attack:');
  console.log("  /api/search?q=' UNION SELECT id,username,password,role,name,name,createdAt FROM users --");
  console.log('');
  console.log('  FOR EDUCATIONAL USE ONLY');
  console.log('');
});
