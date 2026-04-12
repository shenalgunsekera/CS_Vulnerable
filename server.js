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

const app      = express();
const PORT     = 3000;
const MMCC_PORT = 5050;

// ── Middleware ──────────────────────────────────────────────
// VULNERABILITY (D): express.raw() with NO size limit — accepts any payload size.
// A crafted oversized "ping" request will force the server to buffer the entire
// body in memory before responding, just like the original Ping of Death caused
// the OS to allocate a buffer larger than it could safely handle.
app.use('/api/ping', express.raw({ type: '*/*', limit: Infinity }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/**
 * VULNERABILITY (A): Insecure session configuration
 *
 * Problems:
 *  - httpOnly: false  → JavaScript (document.cookie) can read the session cookie
 *  - secure: false    → Cookie sent over plain HTTP (no HTTPS required)
 *  - No maxAge        → Session never expires (no timeout)
 *  - No sameSite      → Cookie sent on cross-site requests (CSRF risk)
 *  - Weak secret      → Easy to brute-force if attacker gets session store access
 */
app.use(session({
  secret:            'cfgs-weak-secret-123',  // VULNERABILITY: Weak, hardcoded secret
  resave:            true,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,   // VULNERABILITY: JS can read document.cookie
    secure:   false,   // VULNERABILITY: Works over HTTP
    // maxAge:  not set → no expiry, session lasts forever
    // sameSite: not set → no CSRF protection
  }
}));

// ── In-Memory Data Store ────────────────────────────────────
// In a real app this would be a database
const USERS = [
  { id: 1, username: 'admin',     password: 'admin123',   role: 'admin',    name: 'Admin User'     },
  { id: 2, username: 'manager1',  password: 'manager123', role: 'manager',  name: 'John Manager'   },
  { id: 3, username: 'employee1', password: 'emp123',     role: 'employee', name: 'Alice Employee' },
  { id: 4, username: 'employee2', password: 'emp456',     role: 'employee', name: 'Bob Employee'   },
];

// VULNERABILITY: Passwords stored in plaintext (no hashing)
let tickets = [
  { id: 1, title: 'Network Issue in 3rd Floor',  description: 'WiFi drops every hour on the 3rd floor.',    status: 'open',   createdBy: 3, createdByName: 'Alice Employee', priority: 'high',   createdAt: new Date(Date.now() - 86400000).toISOString() },
  { id: 2, title: 'Printer Not Working',          description: 'HP printer in accounts dept is offline.',    status: 'open',   createdBy: 4, createdByName: 'Bob Employee',   priority: 'medium', createdAt: new Date(Date.now() - 43200000).toISOString() },
  { id: 3, title: 'Software License Renewal',     description: 'Adobe CC license expires next week.',        status: 'closed', createdBy: 3, createdByName: 'Alice Employee', priority: 'low',    createdAt: new Date(Date.now() - 172800000).toISOString() },
];
let ticketIdCounter = 4;

// ── Helper: Check if logged in ──────────────────────────────
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated. Please log in.' });
  }
  next();
}

// ── AUTH ROUTES ─────────────────────────────────────────────

/**
 * POST /api/login
 *
 * VULNERABILITY (A): Session Fixation / Hijacking
 *  - Session ID is NOT regenerated after login
 *  - An attacker who sets a session ID before login can hijack the session
 *    after the victim logs in (session fixation attack)
 *  - The existing session object is simply populated with user data
 */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: Plain string comparison, no rate limiting
  const user = USERS.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.json({ success: false, message: 'Invalid username or password.' });
  }

  // VULNERABILITY: req.session.regenerate() is NOT called here
  // The old session ID is reused after login, enabling session fixation
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
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// GET /api/me - return current session user
app.get('/api/me', requireLogin, (req, res) => {
  res.json(req.session.user);
});

// ── TICKET ROUTES ───────────────────────────────────────────

// GET /api/tickets
app.get('/api/tickets', requireLogin, (req, res) => {
  res.json(tickets);
});

// POST /api/tickets - Create a new ticket
app.post('/api/tickets', requireLogin, (req, res) => {
  const { title, description, priority } = req.body;

  if (!title || !description) {
    return res.json({ success: false, message: 'Title and description are required.' });
  }

  const ticket = {
    id:            ticketIdCounter++,
    title:         title.trim(),
    description:   description.trim(),
    status:        'open',
    priority:      priority || 'medium',
    createdBy:     req.session.user.id,
    createdByName: req.session.user.name,
    createdAt:     new Date().toISOString(),
  };

  tickets.push(ticket);
  res.json({ success: true, ticket });
});

/**
 * PUT /api/tickets/:id/close
 *
 * VULNERABILITY (B): Privilege Escalation — No backend role check
 *
 * The frontend only shows "Close" buttons to managers and admins.
 * However, this endpoint performs NO role check on the server.
 * Any authenticated user (including employees) can directly call
 * this API and close any ticket.
 *
 * Attack: POST from browser console or any HTTP tool as employee:
 *   fetch('/api/tickets/1/close', { method:'PUT' })
 */
app.put('/api/tickets/:id/close', requireLogin, (req, res) => {
  // VULNERABILITY: No role check — any logged-in user can close tickets
  const ticket = tickets.find(t => t.id === parseInt(req.params.id));

  if (!ticket) return res.json({ success: false, message: 'Ticket not found.' });
  if (ticket.status === 'closed') return res.json({ success: false, message: 'Already closed.' });

  ticket.status = 'closed';
  res.json({ success: true });
});

/**
 * DELETE /api/tickets/:id
 *
 * VULNERABILITY (B): No role check at all — any logged-in user can delete.
 */
app.delete('/api/tickets/:id', requireLogin, (req, res) => {
  // VULNERABILITY: No role check — any authenticated user can delete tickets
  const id = parseInt(req.params.id);
  const exists = tickets.some(t => t.id === id);
  if (!exists) return res.json({ success: false, message: 'Ticket not found.' });

  tickets = tickets.filter(t => t.id !== id);
  res.json({ success: true });
});

// ── ADMIN ROUTES ────────────────────────────────────────────

/**
 * GET /api/admin/users
 *
 * VULNERABILITY (B): Privilege Escalation — No role check
 *
 * This is an "admin-only" endpoint that returns all user data.
 * The frontend only shows admin panel links to admins, but the
 * backend does NOT verify the user's role.
 * Any logged-in user can access this endpoint directly.
 *
 * Attack: In browser console as employee:
 *   fetch('/api/admin/users').then(r=>r.json()).then(console.log)
 */
app.get('/api/admin/users', requireLogin, (req, res) => {
  // VULNERABILITY: requireLogin only checks if logged in, NOT if user is admin
  res.json(USERS.map(u => ({
    id:       u.id,
    username: u.username,
    role:     u.role,
    name:     u.name,
    // VULNERABILITY: Would expose passwords if we returned u directly
  })));
});

// ── SQL INJECTION (C) ────────────────────────────────────────

/**
 * Simulated in-memory database for the SQL injection demo.
 * Mirrors the same data that real app uses, so injection results are realistic.
 * In a real app this would be SQLite / MySQL / PostgreSQL.
 */
const DB = {
  // tickets is a reference — stays in sync with the live array
  get tickets() { return tickets; },
  // users table contains passwords — the prize for a successful injection
  users: USERS,
};

/**
 * GET /api/search?q=QUERY
 *
 * VULNERABILITY (C): SQL Injection via string concatenation
 *
 * The search term is inserted directly into the query string with no
 * sanitisation. An attacker can break out of the LIKE clause and append
 * a UNION SELECT to read any other "table" — including the users table
 * which contains plaintext passwords.
 *
 * Normal use:  /api/search?q=wifi
 * Attack:      /api/search?q=' UNION SELECT id,username,password,role,name,name,name FROM users --
 *
 * Result: All user credentials appear in the search results disguised as tickets.
 */
app.get('/api/search', requireLogin, (req, res) => {
  const q = req.query.q || '';

  // VULNERABILITY: user input lands directly in the query — never do this
  const rawQuery =
    `SELECT id,title,description,status,priority,createdByName,createdAt ` +
    `FROM tickets WHERE title LIKE '%${q}%' OR description LIKE '%${q}%'`;

  try {
    const results = vulnerableExecuteQuery(rawQuery);
    res.json({ success: true, results, rawQuery });
  } catch (e) {
    res.json({ success: false, error: e.message, rawQuery });
  }
});

/**
 * Simulated SQL executor — processes the raw query string against the
 * in-memory DB object and supports UNION SELECT injection.
 */
function vulnerableExecuteQuery(sql) {
  const OUTPUT_COLS = ['id','title','description','status','priority','createdByName','createdAt'];

  // Detect UNION injection pattern
  const unionMatch = sql.match(/UNION\s+SELECT\s+(.+?)\s+FROM\s+(\w+)\s*(?:--.*)?$/i);

  if (unionMatch) {
    const injectedCols = unionMatch[1].split(',').map(c => c.trim().replace(/'/g,''));
    const targetTable  = unionMatch[2].toLowerCase();

    // Base results (the legitimate part of the query, before UNION)
    const baseResults = executeBasicSearch(sql.split(/UNION\s+SELECT/i)[0]);

    // Injected rows from the targeted table (e.g. "users")
    const tableData    = DB[targetTable] || [];
    const injectedRows = tableData.map(row => {
      const result = {};
      OUTPUT_COLS.forEach((col, i) => {
        const src = injectedCols[i];
        result[col] = row[src] !== undefined ? String(row[src]) : src;
      });
      return result;
    });

    return [...baseResults, ...injectedRows];
  }

  return executeBasicSearch(sql);
}

function executeBasicSearch(sql) {
  const OUTPUT_COLS = ['id','title','description','status','priority','createdByName','createdAt'];
  const match = sql.match(/LIKE\s+'%([^%']*?)%'/i);
  const q     = (match ? match[1] : '').toLowerCase();

  return DB.tickets
    .filter(t => !q ||
      t.title.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q))
    .map(t => {
      const r = {};
      OUTPUT_COLS.forEach(c => { r[c] = t[c] !== undefined ? String(t[c]) : ''; });
      return r;
    });
}

// ── PING OF DEATH (D) ────────────────────────────────────────

/**
 * POST /api/ping
 *
 * VULNERABILITY (D): Ping of Death — no payload size validation
 *
 * Classic Ping of Death: attacker sends an ICMP packet whose payload,
 * when reassembled from fragments, exceeds 65,535 bytes. The target OS
 * tries to allocate a buffer for the full packet, overflows, and crashes.
 *
 * Web equivalent here: this endpoint reads and echoes back the entire
 * request body with NO size check. Sending a massive payload forces the
 * Node.js process to buffer all of it in memory simultaneously.
 * A large enough request (e.g. 500 MB) will exhaust heap memory and
 * crash the server with "JavaScript heap out of memory".
 *
 * The endpoint also reflects the byte count back — showing the attacker
 * exactly how much data the server was forced to handle.
 */
app.post('/api/ping', requireLogin, (req, res) => {
  // VULNERABILITY: req.body is the full raw buffer — no size limit applied.
  // The server must hold the entire payload in RAM to reach this line.
  const byteCount = req.body ? req.body.length : 0;

  res.json({
    success:   true,
    message:   'Pong!',
    bytesRead: byteCount,
    // Echo a slice so the browser can confirm data was received
    preview:   req.body ? req.body.slice(0, 64).toString('utf8') : '',
    warning:   'VULNERABILITY: server buffered the entire payload with no size check.',
  });
});

// ── MMCC SERVICE (E) — Port 5050 ────────────────────────────

/**
 * VULNERABILITY (E): Unauthenticated MMCC Service on Port 5050
 *
 * A Multimedia Conference Control (MMCC) service runs on port 5050.
 * This service has NO authentication, NO encryption, and accepts raw
 * TCP connections from ANY host on the network.
 *
 * An attacker can:
 *  1. Discover port 5050 via Nmap:  nmap -sV -p 5050 192.168.8.103
 *  2. Connect directly via netcat:  ncat 192.168.8.103 5050
 *  3. Run commands to extract sensitive server/database info
 *  4. Use the open port as an entry point for further attacks
 *
 * Commands available (no login required):
 *  HELP, INFO, LIST, STATUS, VERSION, CONFIG, QUIT
 */
const mmccServer = net.createServer((socket) => {
  const clientAddr = socket.remoteAddress + ':' + socket.remotePort;
  console.log(`  [MMCC] Client connected: ${clientAddr}`);

  // VULNERABILITY: Service banner reveals version and software details
  // Attackers use banners to fingerprint services and find known exploits
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

  // VULNERABILITY: No authentication — any client gets immediate command access
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
        // VULNERABILITY: Exposes sensitive server and database information
        socket.write(
          'Server Information:\r\n' +
          '  Hostname : metasploitable\r\n' +
          '  OS       : Linux 2.6.24\r\n' +
          '  Service  : MMCC v1.0\r\n' +
          `  Port     : ${MMCC_PORT}\r\n` +
          '  Web App  : http://localhost:3000\r\n' +
          '  DB Host  : localhost\r\n' +
          '  DB Name  : colobo_fort\r\n' +
          '  DB User  : root\r\n' +
          '  DB Pass  : (none)\r\n' +
          '> '
        );
        break;

      case 'LIST':
        // VULNERABILITY: Exposes active user sessions and meeting info
        socket.write(
          'Active Conference Sessions:\r\n' +
          '  Session #1 | User: admin      | Room: Board Meeting  | Status: Active\r\n' +
          '  Session #2 | User: manager1   | Room: IT Review      | Status: Active\r\n' +
          '  Session #3 | User: employee1  | Room: HR Meeting     | Status: Idle\r\n' +
          '> '
        );
        break;

      case 'STATUS':
        // VULNERABILITY: Confirms that auth and encryption are both disabled
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
        // VULNERABILITY: Exposes full config including file paths
        socket.write(
          'Service Configuration:\r\n' +
          '  max_connections : unlimited\r\n' +
          '  auth_required   : false\r\n' +
          '  encryption      : none\r\n' +
          '  log_level       : verbose\r\n' +
          '  web_root        : /var/www/colombofort\r\n' +
          '  config_file     : /var/www/colombofort/config.php\r\n' +
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

  socket.on('close', () => {
    console.log(`  [MMCC] Client disconnected: ${clientAddr}`);
  });

  socket.on('error', (err) => {
    console.log(`  [MMCC] Socket error: ${err.message}`);
  });
});

// VULNERABILITY: Binds to 0.0.0.0 — reachable from any network interface
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
  console.log('  (C) SQL Injection      — UNION attack dumps passwords');
  console.log('  (D) Ping of Death      — POST /api/ping, no size limit');
  console.log(`  (E) MMCC Backdoor      — port ${MMCC_PORT}, no auth required`);
  console.log('');
  console.log('  Attack MMCC: ncat 192.168.8.103 5050');
  console.log('');
  console.log('  FOR EDUCATIONAL USE ONLY');
  console.log('');
});