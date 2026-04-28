import 'dotenv/config';
import express from 'express';
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import https from 'https';
import fs from 'fs';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET not found in environment variables');
  process.exit(1);
}

// JWT Middleware
function authenticateToken(req: any, res: any, next: any) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Unauthorized: Missing token' });

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.status(403).json({ error: 'Forbidden: Invalid token' });

    // Check IP and Session restriction
    db.get('SELECT currentIp, sessionId FROM users WHERE id = ?', [user.id], (dbErr, row: any) => {
      if (dbErr || !row) return res.status(403).json({ error: 'Forbidden: Session expired or user not found' });

      const currentRequestIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

      // Check sessionId (primary check for multi-device/multi-browser)
      if (user.sessionId && row.sessionId && user.sessionId !== row.sessionId) {
        return res.status(403).json({ error: 'Session invalidated: Access from another device or browser detected' });
      }

      // Check IP restriction (optional/fallback)
      if (row.currentIp && row.currentIp !== currentRequestIp) {
        // We still check IP, but sessionId is more precise for multiple browsers on same device
        // return res.status(403).json({ error: 'Session invalidated: Access from another device or IP detected' });
      }

      req.user = user;
      next();
    });
  });
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 5001;
const HTTPS_PORT = process.env.HTTPS_PORT ? parseInt(process.env.HTTPS_PORT) : 5443;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3001', 'http://127.0.0.1:3001'],
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));

const requestCounts = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS = 100;

function rateLimitMiddleware(req: any, res: any, next: any) {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const now = Date.now();
  const record = requestCounts.get(ip);

  if (!record || now > record.resetTime) {
    requestCounts.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    next();
    return;
  }

  if (record.count >= MAX_REQUESTS) {
    res.status(429).json({ error: 'Too many requests. Please try again later.' });
    return;
  }

  record.count++;
  next();
}

app.use(rateLimitMiddleware);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', database: db ? 'connected' : 'disconnected' });
});
const dbPath = path.resolve(__dirname, 'microlend.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(() => {
    // Customers Table
    db.run(`CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT,
      address TEXT,
      idProof TEXT,
      referenceName TEXT,
      referencePhone TEXT,
      joinedAt TEXT,
      createdAt TEXT NOT NULL,
      createdBy TEXT
    )`);

    // Loans Table
    db.run(`CREATE TABLE IF NOT EXISTS loans (
      id TEXT PRIMARY KEY,
      customerId TEXT NOT NULL,
      loanAmount REAL NOT NULL,
      profit REAL NOT NULL,
      disbursedAmount REAL NOT NULL,
      tenureDays INTEGER NOT NULL,
      emiPerDay REAL NOT NULL,
      startDate TEXT NOT NULL,
      endDate TEXT NOT NULL,
      status TEXT NOT NULL,
      createdAt TEXT,
      createdBy TEXT,
      FOREIGN KEY (customerId) REFERENCES customers(id)
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_loans_customerId ON loans(customerId)`);

    // Payments Table
    db.run(`CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      loanId TEXT NOT NULL,
      date TEXT NOT NULL,
      amountPaid REAL NOT NULL,
      paymentMethod TEXT DEFAULT 'Cash',
      FOREIGN KEY (loanId) REFERENCES loans(id)
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_payments_loanId ON payments(loanId)`);

    // Migration for paymentMethod
    db.run(`ALTER TABLE payments ADD COLUMN paymentMethod TEXT DEFAULT 'Cash'`, (err) => {
      // Silently ignore if column already exists
    });

    // Expenses Table
    db.run(`CREATE TABLE IF NOT EXISTS expenses (
      id TEXT PRIMARY KEY,
      amount REAL NOT NULL,
      category TEXT NOT NULL,
      date TEXT NOT NULL,
      notes TEXT
    )`);

    // Ledger Table
    db.run(`CREATE TABLE IF NOT EXISTS ledger (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      category TEXT NOT NULL,
      date TEXT NOT NULL,
      referenceId TEXT,
      notes TEXT
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_ledger_referenceId ON ledger(referenceId)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_ledger_date ON ledger(date)`);

    // Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      securityQuestion TEXT,
      securityAnswer TEXT,
      phone TEXT,
      status TEXT DEFAULT 'pending',
      currentIp TEXT,
      lastLoginAt TEXT,
      sessionId TEXT
    )`);

    // Migrations for existing deployments
    const userColumns = [
      'securityQuestion TEXT',
      'securityAnswer TEXT',
      'phone TEXT',
      'status TEXT DEFAULT "pending"',
      'currentIp TEXT',
      'lastLoginAt TEXT',
      'sessionId TEXT'
    ];
    userColumns.forEach(col => {
      db.run(`ALTER TABLE users ADD COLUMN ${col}`, (err) => {
        // Silently ignore if column already exists
      });
    });

    // Audit Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      userId TEXT,
      userName TEXT,
      action TEXT NOT NULL,
      details TEXT,
      entityType TEXT,
      entityId TEXT,
      createdAt TEXT
    )`);

    // Settings Table
    db.run(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updatedAt TEXT
    )`, () => {
      // Seed default settings
      const defaults = [
        ['idle_timeout_mins', '15'],
        ['license_limit', '10'],
        ['commission_rate', '10']
      ];
      defaults.forEach(([key, val]) => {
        db.run(`INSERT OR IGNORE INTO settings (key, value, updatedAt) VALUES (?, ?, ?)`, [key, val, new Date().toISOString()]);
      });
    });


    // Migration for customer reference fields
    const customerColumns = [
      'idProof TEXT',
      'referenceName TEXT',
      'referencePhone TEXT',
      'joinedAt TEXT'
    ];
    customerColumns.forEach(col => {
      db.run(`ALTER TABLE customers ADD COLUMN ${col}`, (err) => {
        // Silently ignore if column already exists
      });
    });
    db.run(`CREATE INDEX IF NOT EXISTS idx_audit_logs_createdAt ON audit_logs(createdAt)`);
  });
}

// Audit Log Helper
function logAction(userId: string | null, userName: string | null, action: string, details: string | null = null, entityType: string | null = null, entityId: string | null = null) {
  const id = uuidv4();
  const createdAt = new Date().toISOString();
  db.run(`INSERT INTO audit_logs (id, userId, userName, action, details, entityType, entityId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, userId, userName, action, details, entityType, entityId, createdAt],
    (err) => {
      if (err) console.error('Error logging action:', err.message);
    });
}

function validatePassword(password: string): boolean {
  // Regex: 9+ chars, 1+ lowercase, 1+ uppercase, 1+ digit, 1+ special char
  if (password.length < 9) return false;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[@$!%*?&#^()_+\-=<>?/[\]{}|.,;:'\"~]/.test(password);
  return hasLower && hasUpper && hasDigit && hasSpecial;
}

function canPerformWrite(req: any, res: any): boolean {
  if (req.user.role === 'viewer') {
    res.status(403).json({ error: 'Viewers cannot perform write operations' });
    return false;
  }
  return true;
}

// API Routes
// Audit Logs
app.get('/api/audit-logs', authenticateToken, (req, res) => {
  db.all('SELECT * FROM audit_logs ORDER BY createdAt DESC LIMIT 500', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Users & Auth
app.get('/api/users', authenticateToken, (req, res) => {
  db.all('SELECT id, name, email, role, status, phone, lastLoginAt, currentIp FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/admin/pending-users', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
  db.all("SELECT id, name, email, role, status, phone, lastLoginAt, currentIp FROM users WHERE status = 'pending'", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Fix customer IDs migration
app.post('/api/admin/fix-null-ids', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });

  // Get all customers with null IDs
  db.all("SELECT rowid, id, phone FROM customers WHERE id IS NULL", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    if (rows.length === 0) {
      return res.json({ message: 'No null IDs found', fixed: 0 });
    }

    // Fix them one by one
    let fixed = 0;
    let completed = 0;

    if (rows.length === 0) {
      res.json({ message: 'No null IDs to fix', fixed: 0 });
      return;
    }

    rows.forEach((row: any) => {
      const newId = uuidv4();

      // Update loans with phone first
      if (row.phone) {
        db.run("UPDATE loans SET customerId = ? WHERE customerId = ?", [newId, row.phone], (err) => {
          if (!err) {
            db.run("UPDATE customers SET id = ? WHERE rowid = ?", [newId, row.rowid], (err2) => {
              if (!err2) fixed++;
              completed++;
              if (completed === rows.length) {
                res.json({ message: 'Migration complete', fixed });
              }
            });
          } else {
            completed++;
            if (completed === rows.length) {
              res.json({ message: 'Migration complete', fixed });
            }
          }
        });
      } else {
        db.run("UPDATE customers SET id = ? WHERE rowid = ?", [newId, row.rowid], (err2) => {
          if (!err2) fixed++;
          completed++;
          if (completed === rows.length) {
            res.json({ message: 'Migration complete', fixed });
          }
        });
      }
    });
  });
});

app.put('/api/admin/approve-user/:id', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
  const { status } = req.body; // 'approved' or 'rejected'

  if (status === 'approved') {
    // Check license limit
    db.get("SELECT value FROM settings WHERE key = 'license_limit'", [], (err, setting: any) => {
      if (err) return res.status(500).json({ error: err.message });
      const limit = parseInt(setting?.value || '10');

      db.get("SELECT COUNT(*) as count FROM users WHERE status = 'approved'", [], (err, row: any) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row.count >= limit) {
          return res.status(400).json({ error: `License limit reached (${limit}). Cannot approve more users.` });
        }
        updateStatus();
      });
    });
  } else {
    updateStatus();
  }

  function updateStatus() {
    db.run('UPDATE users SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      logAction(req.user.id, req.user.name, 'APPROVE_USER', `User status updated to ${status} for ${req.params.id}`, 'USER', req.params.id);
      res.json({ message: `User status updated to ${status}` });
    });
  }
});

// Settings Endpoints
app.get('/api/settings', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'operations') return res.status(403).json({ error: 'Unauthorized' });
  
  db.all('SELECT * FROM settings', [], (err, rows: any[]) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Filter for operations
    if (req.user.role === 'operations') {
      return res.json(rows.filter(r => r.key === 'commission_rate'));
    }
    
    res.json(rows);
  });
});

app.get('/api/public-settings', authenticateToken, (req, res) => {
  // Only expose non-sensitive settings to all logged-in users
  db.all("SELECT key, value FROM settings WHERE key IN ('idle_timeout_mins', 'commission_rate')", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.put('/api/settings', authenticateToken, (req: any, res) => {
  const { key, value } = req.body;
  
  // Restriction: Operations can only edit commission_rate
  if (req.user.role !== 'admin') {
    if (req.user.role !== 'operations' || key !== 'commission_rate') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
  }

  const updatedAt = new Date().toISOString();
  db.run('INSERT OR REPLACE INTO settings (key, value, updatedAt) VALUES (?, ?, ?)', [key, value, updatedAt], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    logAction(req.user.id, req.user.name, 'UPDATE_SETTING', `Updated setting ${key} to ${value}`, 'SETTING', key);
    res.json({ message: `Setting ${key} updated` });
  });
});

app.delete('/api/admin/users/:id', authenticateToken, (req: any, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
  const targetId = req.params.id;
  const adminId = req.user.id;

  if (targetId === adminId) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }

  db.get('SELECT name, email FROM users WHERE id = ?', [targetId], (err, targetUser: any) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!targetUser) return res.status(404).json({ error: 'User not found' });

    db.run('DELETE FROM users WHERE id = ?', [targetId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      logAction(adminId, req.user.name, 'DELETE_USER', `Deleted user ${targetUser.name} (${targetUser.email})`, 'USER', targetId);
      res.status(204).send();
    });
  });
});

app.post('/api/users', (req, res) => {
  const { id, name, email, password, role, securityQuestion, securityAnswer, phone } = req.body;

  if (role === 'admin') {
    db.get('SELECT id FROM users WHERE role = ?', ['admin'], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (row) {
        return res.status(400).json({ error: 'An Admin account already exists. Only one Admin is allowed.' });
      }
      insertUser();
    });
  } else {
    insertUser();
  }

  async function insertUser() {
    try {
      if (!validatePassword(password)) {
        return res.status(400).json({ error: 'Password must be at least 9 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const hashedAnswer = await bcrypt.hash(securityAnswer, 10);
      const userStatus = role === 'admin' ? 'approved' : 'pending';
      db.run(`INSERT INTO users (id, name, email, password, role, securityQuestion, securityAnswer, phone, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, name, email, hashedPassword, role, securityQuestion, hashedAnswer, phone, userStatus],
        (err) => {
          if (err) return res.status(500).json({ error: 'Database error during registration' });
          logAction(id, name, 'REGISTER_USER', `Registered as ${role} (status: ${userStatus})`, 'USER', id);

          if (userStatus === 'approved') {
            const sessionId = uuidv4();
            db.run('UPDATE users SET sessionId = ? WHERE id = ?', [sessionId, id], (err) => {
              if (err) console.error('Error updating sessionId on registration:', err.message);

              const token = jwt.sign({ id, name, role, sessionId }, JWT_SECRET, { expiresIn: '1h' });
              const userWithoutPassword = { id, name, email, role, phone, status: userStatus, sessionId };
              res.status(201).json({ id, token, user: userWithoutPassword });
            });
          } else {
            res.status(201).json({ id, message: 'Registration successful. Pending admin approval.' });
          }
        });
    } catch (error) {
      res.status(500).json({ error: 'Error hashing password' });
    }
  }
});

const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

function checkRateLimit(identifier: string): boolean {
  const now = Date.now();
  const attempt = loginAttempts.get(identifier);
  if (!attempt) {
    loginAttempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }
  if (now - attempt.lastAttempt > LOCKOUT_DURATION) {
    loginAttempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }
  if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
    return false;
  }
  attempt.count++;
  attempt.lastAttempt = now;
  return true;
}

app.get('/api/users/security-question/:identifier', (req, res) => {
  const identifier = req.params.identifier;
  db.get('SELECT securityQuestion FROM users WHERE email = ? OR phone = ?', [identifier, identifier], (err, row: any) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row && row.securityQuestion) {
      res.json({ securityQuestion: row.securityQuestion });
    } else {
      res.status(404).json({ error: 'User or security question not found' });
    }
  });
});

app.post('/api/users/reset-password', (req, res) => {
  const { identifier, securityAnswer, newPassword } = req.body;

  if (!checkRateLimit(identifier + '_reset')) {
    return res.status(429).json({ error: 'Too many password reset attempts. Please try again after 15 minutes.' });
  }
  if (!validatePassword(newPassword)) {
    return res.status(400).json({ error: 'Password must be at least 9 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.' });
  }
  db.get('SELECT id, securityAnswer FROM users WHERE (email = ? OR phone = ?)', [identifier, identifier], async (err, row: any) => {
    if (err) return res.status(500).json({ error: 'Database error during reset' });
    if (row && row.securityAnswer) {
      try {
        const isAnswerMatch = await bcrypt.compare(securityAnswer, row.securityAnswer);
        if (!isAnswerMatch) {
          return res.status(401).json({ error: 'Invalid security answer' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, row.id], (err) => {
          if (err) return res.status(500).json({ error: 'Failed to update password' });
          res.json({ message: 'Password reset successful' });
        });
      } catch (error) {
        res.status(500).json({ error: 'Error hashing password' });
      }
    } else {
      res.status(401).json({ error: 'Invalid security answer' });
    }
  });
});
app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body;

  if (!checkRateLimit(identifier)) {
    return res.status(429).json({ error: 'Too many login attempts. Please try again after 15 minutes.' });
  }

  db.get('SELECT id, name, email, password, role, status, securityAnswer FROM users WHERE email = ? OR phone = ?', [identifier, identifier], async (err, row: any) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) {
      try {
        const isMatch = await bcrypt.compare(password, row.password);
        if (isMatch) {
          loginAttempts.delete(identifier);
          if (row.status !== 'approved') {
            return res.status(403).json({ error: 'Your account is pending admin approval' });
          }

          const currentLoginIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

          const lastLoginAt = new Date().toISOString();
          const sessionId = uuidv4();

          db.run('UPDATE users SET currentIp = ?, lastLoginAt = ?, sessionId = ? WHERE id = ?', [currentLoginIp, lastLoginAt, sessionId, row.id], (updateErr) => {
            if (updateErr) console.error('Error updating login metadata:', updateErr.message);

            logAction(row.id, row.name, 'LOGIN', `User logged in from ${currentLoginIp}`, 'USER', row.id);
            const { password: _, securityAnswer: __, ...userData } = row;
            const token = jwt.sign({ id: row.id, name: row.name, role: row.role, sessionId }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ token, user: { ...userData, currentIp: currentLoginIp, lastLoginAt, sessionId } });
          });
        } else {
          res.status(401).json({ error: 'Invalid email/phone or password' });
        }
      } catch (error) {
        res.status(500).json({ error: 'Error verifying password' });
      }
    } else {
      res.status(401).json({ error: 'Invalid email/phone or password' });
    }
  });
});

// Customers
app.get('/api/customers', authenticateToken, (req, res) => {
  db.all('SELECT * FROM customers', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/customers', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { id: providedId, name, phone, address, idProof, referenceName, referencePhone, joinedAt, createdAt, createdBy } = req.body;
  const id = providedId || uuidv4();

  // Check if ID Proof already exists
  db.get('SELECT id FROM customers WHERE idProof = ?', [idProof], (err, row: any) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) {
      return res.status(409).json({ 
        error: 'A customer with this ID Proof already exists.',
        existingId: row.id 
      });
    }

    db.run(`INSERT INTO customers (id, name, phone, address, idProof, referenceName, referencePhone, joinedAt, createdAt, createdBy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, name, phone, address, idProof, referenceName, referencePhone, joinedAt, createdAt, createdBy],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        const auditUserId = (req as any).user?.id || createdBy;
        const auditUserName = (req as any).user?.name || 'Unknown';
        logAction(auditUserId, auditUserName, 'CREATE_CUSTOMER', `Created customer ${name}`, 'CUSTOMER', id);
        res.status(201).json({ id });
      });
  });
});

app.put('/api/customers/:id', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { name, phone, address, idProof, referenceName, referencePhone, joinedAt } = req.body;
  const customerId = req.params.id;

  // Check if ID Proof already exists for a different user
  db.get('SELECT id FROM customers WHERE idProof = ? AND id != ?', [idProof, customerId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) {
      return res.status(400).json({ error: 'A different customer with this ID Proof already exists.' });
    }

    db.run(
      `UPDATE customers SET name = ?, phone = ?, address = ?, idProof = ?, referenceName = ?, referencePhone = ?, joinedAt = ? WHERE id = ?`,
      [name, phone, address, idProof, referenceName, referencePhone, joinedAt, customerId],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        const auditUserId = (req as any).user?.id || null;
        const auditUserName = (req as any).user?.name || 'Unknown';
        logAction(auditUserId, auditUserName, 'UPDATE_CUSTOMER', `Updated details for customer ${name}`, 'CUSTOMER', customerId);
        res.status(200).json({ id: customerId });
      }
    );
  });
});

app.delete('/api/customers/:id', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const role = req.user?.role;
  if (role !== 'admin') {
    return res.status(403).json({ error: 'Only administrators can delete customers' });
  }
  const customerId = req.params.id;

  // Check for any loans
  db.get('SELECT COUNT(*) as count FROM loans WHERE customerId = ?', [customerId], (err, row: any) => {
    if (err) return res.status(500).json({ error: err.message });

    if (row.count > 0) {
      return res.status(400).json({ error: 'Cannot delete customer with existing loan records' });
    }

    db.get('SELECT name FROM customers WHERE id = ?', [customerId], (err, customer: any) => {
      const customerName = customer ? customer.name : customerId;

      db.run('DELETE FROM customers WHERE id = ?', customerId, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        const auditUserId = (req as any).user?.id || null;
        const auditUserName = (req as any).user?.name || null;
        logAction(auditUserId, auditUserName, 'DELETE_CUSTOMER', `Deleted customer ${customerName}`, 'CUSTOMER', customerId);
        res.status(204).end();
      });
    });
  });
});

// Loans
app.get('/api/loans', authenticateToken, (req, res) => {
  db.all('SELECT * FROM loans', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/loans', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { id: providedId, customerId, loanAmount, tenureDays, startDate, createdBy, commissionRate: providedRate } = req.body;
  const id = providedId || uuidv4();
  const auditUserId = req.user.id;
  const auditUserName = req.user.name;

  db.get("SELECT value FROM settings WHERE key = 'commission_rate'", (err, setting: any) => {
    const rate = (providedRate !== undefined ? parseFloat(providedRate) : parseFloat(setting?.value || '10')) / 100;
    const profit = loanAmount * rate;
    const disbursedAmount = loanAmount - profit;
    const emiPerDay = loanAmount / tenureDays;
    // Calculate endDate: startDate + tenureDays
    const startObj = new Date(startDate);
    const endObj = new Date(startObj.getTime() + tenureDays * 24 * 60 * 60 * 1000);
    const endDate = endObj.toISOString().split('T')[0];
    const createdAt = new Date().toISOString();
    const status = 'active';

    db.serialize(() => {
      db.run('BEGIN TRANSACTION');

      // Check for sufficient capital
      db.get("SELECT SUM(CASE WHEN type = 'credit' THEN amount ELSE -amount END) as balance FROM ledger", [], (err, row: any) => {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err.message });
        }

        const currentBalance = row.balance || 0;
        if (currentBalance < disbursedAmount) {
          db.run('ROLLBACK');
          return res.status(400).json({
            error: `Insufficient Capital. Current Cash in Hand: ${currentBalance}. Required: ${disbursedAmount}.`
          });
        }

        // Verify customer exists
        db.get('SELECT id FROM customers WHERE id = ?', [customerId], (err, customerRow) => {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: err.message });
          }
          if (!customerRow) {
            db.run('ROLLBACK');
            return res.status(404).json({ error: `Customer with ID ${customerId} not found. Loan cannot be created.` });
          }

          db.run(`INSERT INTO loans (id, customerId, loanAmount, profit, disbursedAmount, tenureDays, emiPerDay, startDate, endDate, status, createdAt, createdBy) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, customerId, loanAmount, profit, disbursedAmount, tenureDays, emiPerDay, startDate, endDate, status, createdAt, createdBy || auditUserName],
            (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: err.message });
              }

              db.get('SELECT name FROM customers WHERE id = ?', [customerId], (err, customer: any) => {
                const customerName = customer ? customer.name : customerId;

                // Ledger: Disbursement (Debit)
                const ledgerId1 = uuidv4();
                db.run('INSERT INTO ledger (id, type, amount, category, date, referenceId, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
                  [ledgerId1, 'debit', loanAmount, 'loan_disbursement', startDate, id, `Loan amount of ${loanAmount} issued to customer ${customerName}`],
                  (err) => {
                    if (err) {
                      db.run('ROLLBACK');
                      return res.status(500).json({ error: err.message });
                    }

                    // Ledger: Commission (Credit)
                    const ledgerId2 = uuidv4();
                    db.run('INSERT INTO ledger (id, type, amount, category, date, referenceId, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
                      [ledgerId2, 'credit', profit, 'loan_commission', startDate, id, `Upfront commission for loan to ${customerName}`],
                      (err) => {
                        if (err) {
                          db.run('ROLLBACK');
                          return res.status(500).json({ error: err.message });
                        }

                        db.run('COMMIT', (err) => {
                          if (err) {
                            db.run('ROLLBACK');
                            return res.status(500).json({ error: err.message });
                          }
                          logAction(auditUserId, auditUserName, 'CREATE_LOAN', `Issued loan of ${loanAmount} to customer ${customerName}`, 'LOAN', id);
                          res.status(201).json({ id, profit, disbursedAmount, emiPerDay, endDate });
                        });
                      }
                    );
                  }
                );
              });
            }
          );
        });
      });
    });
  });
});

app.put('/api/loans/:id', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { status } = req.body;
  const role = (req as any).user?.role;

  if (status === 'defaulted' && role !== 'admin') {
    return res.status(403).json({ error: 'Only administrators can mark loans as defaulted' });
  }

  db.get('SELECT c.name FROM loans l JOIN customers c ON l.customerId = c.id WHERE l.id = ?', [req.params.id], (err, customer: any) => {
    const customerName = customer ? customer.name : 'Unknown';

    db.run('UPDATE loans SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      const auditUserId = (req as any).user?.id || null;
      const auditUserName = (req as any).user?.name || null;
      logAction(auditUserId, auditUserName, 'UPDATE_LOAN', `Updated loan for customer ${customerName} status to ${status}`, 'LOAN', req.params.id);
      res.status(204).end();
    });
  });
});

app.delete('/api/loans/:id', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const role = req.user?.role;
  if (role !== 'admin') {
    return res.status(403).json({ error: 'Only administrators can delete loans' });
  }
  const loanId = req.params.id;

  // Check for payments
  db.get('SELECT COUNT(*) as count FROM payments WHERE loanId = ?', [loanId], (err, row: any) => {
    if (err) return res.status(500).json({ error: err.message });

    if (row.count > 0) {
      return res.status(400).json({ error: 'Cannot delete loan with payment records' });
    }

    db.get('SELECT c.name FROM loans l JOIN customers c ON l.customerId = c.id WHERE l.id = ?', [loanId], (err, customer: any) => {
      const customerName = customer ? customer.name : 'Unknown';

      db.run('DELETE FROM loans WHERE id = ?', loanId, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        const auditUserId = (req as any).user?.id || null;
        const auditUserName = (req as any).user?.name || null;
        logAction(auditUserId, auditUserName, 'DELETE_LOAN', `Deleted loan for customer ${customerName}`, 'LOAN', loanId);
        res.status(204).end();
      });
    });
  });
});

// Payments
app.get('/api/payments', authenticateToken, (req, res) => {
  db.all('SELECT * FROM payments', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/payments', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { id, loanId, date, amountPaid, paymentMethod } = req.body;
  const auditUserId = req.user.id;
  const auditUserName = req.user.name;

  const today = new Date().toISOString().split('T')[0];
  if (date > today) {
    return res.status(400).json({
      error: `Collection date (${date}) cannot be in the future.`
    });
  }

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    db.get('SELECT startDate, customerId, loanAmount, status FROM loans WHERE id = ?', [loanId], (err, loan: any) => {
      if (err || !loan) {
        db.run('ROLLBACK');
        return res.status(err ? 500 : 404).json({ error: err ? err.message : 'Loan not found' });
      }

      if (date < loan.startDate) {
        db.run('ROLLBACK');
        return res.status(400).json({
          error: `Collection date (${date}) cannot be earlier than loan issued date (${loan.startDate}).`
        });
      }

      db.run('INSERT INTO payments (id, loanId, date, amountPaid, paymentMethod) VALUES (?, ?, ?, ?, ?)',
        [id, loanId, date, amountPaid, paymentMethod || 'Cash'],
        (err) => {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: err.message });
          }

          db.get('SELECT name FROM customers WHERE id = ?', [loan.customerId], (err, customer: any) => {
            const customerName = customer ? customer.name : 'Unknown';

            // Ledger: Collection (Credit)
            const ledgerId = uuidv4();
            db.run('INSERT INTO ledger (id, type, amount, category, date, referenceId, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
              [ledgerId, 'credit', amountPaid, 'loan_collection', date, id, `Payment collected from ${customerName} (${paymentMethod || 'Cash'})`],
              (err) => {
                if (err) {
                  db.run('ROLLBACK');
                  return res.status(500).json({ error: err.message });
                }

                // Check auto-complete
                db.get('SELECT SUM(amountPaid) as totalPaid FROM payments WHERE loanId = ?', [loanId], (err, row: any) => {
                  if (err) {
                    db.run('ROLLBACK');
                    return res.status(500).json({ error: err.message });
                  }

                  const totalPaid = row.totalPaid || 0;
                  if (totalPaid >= loan.loanAmount && loan.status === 'active') {
                    db.run('UPDATE loans SET status = ? WHERE id = ?', ['completed', loanId], (err) => {
                      if (err) {
                        db.run('ROLLBACK');
                        return res.status(500).json({ error: err.message });
                      }
                      finish();
                    });
                  } else {
                    finish();
                  }

                  function finish() {
                    db.run('COMMIT', (err) => {
                      if (err) {
                        db.run('ROLLBACK');
                        return res.status(500).json({ error: err.message });
                      }
                      logAction(auditUserId, auditUserName, 'ADD_COLLECTION', `Added collection of ${amountPaid} for customer ${customerName}`, 'PAYMENT', id);
                      res.status(201).json({ id });
                    });
                  }
                });
              }
            );
          });
        }
      );
    });
  });
});

app.delete('/api/payments/:id', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const role = req.user?.role;
  if (role !== 'admin') {
    return res.status(403).json({ error: 'Only administrators can delete collections' });
  }
  db.run('DELETE FROM payments WHERE id = ?', [req.params.id], (err) => {
    if (err) {
      console.error('DELETE Payment Error:', err);
      return res.status(500).json({ error: err.message });
    }
    const auditUserId = (req as any).user?.id || null;
    const auditUserName = (req as any).user?.name || null;
    logAction(auditUserId, auditUserName, 'DELETE_COLLECTION', `Deleted collection ${req.params.id}`, 'PAYMENT', req.params.id);
    res.status(204).end();
  });
});

app.put('/api/payments/:id', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { amountPaid, date, paymentMethod } = req.body;
  const paymentId = req.params.id;
  const auditUserId = req.user.id;
  const auditUserName = req.user.name;

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only administrators can correct collections' });
  }

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    // Get old values for logging and sync
    db.get('SELECT p.*, c.name as customerName, l.loanAmount, l.status as loanStatus FROM payments p JOIN loans l ON p.loanId = l.id JOIN customers c ON l.customerId = c.id WHERE p.id = ?', [paymentId], (err, oldRow: any) => {
      if (err || !oldRow) {
        db.run('ROLLBACK');
        return res.status(err ? 500 : 404).json({ error: err ? err.message : 'Payment not found' });
      }

      db.run('UPDATE payments SET amountPaid = ?, date = ?, paymentMethod = ? WHERE id = ?', [amountPaid, date, paymentMethod || 'Cash', paymentId], (err) => {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err.message });
        }

        // Sync Ledger
        db.run('UPDATE ledger SET amount = ?, date = ?, notes = ? WHERE referenceId = ?',
          [amountPaid, date, `Payment collected from ${oldRow.customerName} (Corrected - ${paymentMethod || 'Cash'})`, paymentId],
          (err) => {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: err.message });
            }

            // Sync Loan Status
            db.get('SELECT SUM(amountPaid) as totalPaid FROM payments WHERE loanId = ?', [oldRow.loanId], (err, row: any) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: err.message });
              }

              const totalPaid = row.totalPaid || 0;
              const newStatus = totalPaid >= oldRow.loanAmount ? 'completed' : 'active';

              if (newStatus !== oldRow.loanStatus && (oldRow.loanStatus === 'active' || oldRow.loanStatus === 'completed')) {
                db.run('UPDATE loans SET status = ? WHERE id = ?', [newStatus, oldRow.loanId], (err) => {
                  if (err) {
                    db.run('ROLLBACK');
                    return res.status(500).json({ error: err.message });
                  }
                  finalize();
                });
              } else {
                finalize();
              }

              function finalize() {
                db.run('COMMIT', (err) => {
                  if (err) {
                    db.run('ROLLBACK');
                    return res.status(500).json({ error: err.message });
                  }
                  const details = `Corrected collection for ${oldRow.customerName}. Amount: ${oldRow.amountPaid} -> ${amountPaid}, Date: ${oldRow.date} -> ${date}`;
                  logAction(auditUserId, auditUserName, 'UPDATE_COLLECTION', details, 'PAYMENT', paymentId);
                  res.json({ message: 'Payment updated successfully' });
                });
              }
            });
          }
        );
      });
    });
  });
});

app.put('/api/ledger/by-reference/:id', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { amount, date, notes } = req.body;
  const referenceId = req.params.id;
  const role = (req as any).user?.role;

  if (role !== 'admin') {
    return res.status(403).json({ error: 'Only administrators can update ledger entries' });
  }

  db.run('UPDATE ledger SET amount = ?, date = ?, notes = ? WHERE referenceId = ?', [amount, date, notes, referenceId], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Ledger entry updated successfully' });
  });
});

// Expenses
app.get('/api/expenses', authenticateToken, (req, res) => {
  db.all('SELECT * FROM expenses', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/expenses', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { id, amount, category, date, notes } = req.body;
  db.run('INSERT INTO expenses (id, amount, category, date, notes) VALUES (?, ?, ?, ?, ?)',
    [id, amount, category, date, notes],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      const auditUserId = (req as any).user?.id || null;
      const auditUserName = (req as any).user?.name || null;
      logAction(auditUserId, auditUserName, 'ADD_EXPENSE', `Added expense of ${amount} for ${category}`, 'EXPENSE', id);
      res.status(201).json({ id });
    });
});

// Ledger
app.get('/api/ledger', authenticateToken, (req, res) => {
  db.all('SELECT * FROM ledger', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/ledger', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const { id, type, amount, category, date, referenceId, notes } = req.body;

  if (category === 'withdrawal') {
    db.get("SELECT SUM(CASE WHEN type = 'credit' THEN amount ELSE -amount END) as balance FROM ledger", [], (err, row: any) => {
      if (err) return res.status(500).json({ error: err.message });

      const currentBalance = row.balance || 0;
      if (currentBalance < amount) {
        return res.status(400).json({
          error: `Insufficient Capital to record this withdrawal. Current Cash in Hand: ${currentBalance}. Required: ${amount}.`
        });
      }
      insertLedger();
    });
  } else {
    insertLedger();
  }

  function insertLedger() {
    db.run('INSERT INTO ledger (id, type, amount, category, date, referenceId, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, type, amount, category, date, referenceId, notes],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        if (category === 'capital') {
          const auditUserId = (req as any).user?.id || null;
          const auditUserName = (req as any).user?.name || null;
          logAction(auditUserId, auditUserName, 'ADD_CAPITAL', `Added capital of ${amount}`, 'LEDGER', id);
        } else if (category === 'withdrawal') {
          const auditUserId = (req as any).user?.id || null;
          const auditUserName = (req as any).user?.name || null;
          logAction(auditUserId, auditUserName, 'WITHDRAW_CAPITAL', `Withdrew capital of ${amount}`, 'LEDGER', id);
        }
        res.status(201).json({ id });
      });
  }
});

app.delete('/api/ledger', authenticateToken, (req: any, res) => {
  if (!canPerformWrite(req, res)) return;
  const role = req.user?.role;
  if (role !== 'admin') return res.status(403).json({ error: 'Permission denied' });

  const { referenceId } = req.query;
  if (referenceId) {
    db.run('DELETE FROM ledger WHERE referenceId = ?', referenceId, (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(204).end();
    });
  } else {
    res.status(400).json({ error: 'referenceId is required' });
  }
});

// Database Explorer Endpoints
const ALLOWED_TABLES = ['customers', 'loans', 'payments', 'expenses', 'ledger', 'users', 'audit_logs'];

app.get('/api/db/tables', authenticateToken, (req, res) => {
  const role = (req as any).user?.role;
  if (role !== 'admin') return res.status(403).json({ error: 'Permission denied' });

  db.all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    const safeTables = rows.map((r: any) => r.name).filter((name: string) => ALLOWED_TABLES.includes(name));
    res.json(safeTables);
  });
});

app.get('/api/db/tables/:name', authenticateToken, (req, res) => {
  const role = (req as any).user?.role;
  if (role !== 'admin') return res.status(403).json({ error: 'Permission denied' });

  const tableName = req.params.name;
  if (!ALLOWED_TABLES.includes(tableName)) {
    return res.status(400).json({ error: 'Invalid table name' });
  }

  // Scrub password/securityAnswer from users table response
  const selectQuery = tableName === 'users'
    ? 'SELECT id, name, email, role, phone FROM users'
    : `SELECT * FROM ${tableName}`;

  db.all(selectQuery, (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

const SSL_KEY_PATH = process.env.SSL_KEY_PATH;
const SSL_CERT_PATH = process.env.SSL_CERT_PATH;

function startServer() {
  if (SSL_KEY_PATH && SSL_CERT_PATH && fs.existsSync(SSL_KEY_PATH) && fs.existsSync(SSL_CERT_PATH)) {
    const httpsOptions = {
      key: fs.readFileSync(SSL_KEY_PATH),
      cert: fs.readFileSync(SSL_CERT_PATH),
    };
    https.createServer(httpsOptions, app).listen(HTTPS_PORT, '0.0.0.0', () => {
      console.log(`Server running on https://0.0.0.0:${HTTPS_PORT} (HTTPS enabled)`);
      console.log(`Server is accessible on your local network.`);
    });
    console.log(`Note: HTTPS is enabled. Update your client to use https://localhost:${HTTPS_PORT}`);
  } else {
    if (process.env.NODE_ENV === 'production') {
      console.warn('WARNING: Running in production without SSL certificates. Set SSL_KEY_PATH and SSL_CERT_PATH env vars.');
    }
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on http://0.0.0.0:${PORT}`);
      console.log(`Server is accessible on your local network.`);
      console.log(`For production, set SSL_KEY_PATH and SSL_CERT_PATH for HTTPS.`);
    });
  }
}

startServer();
