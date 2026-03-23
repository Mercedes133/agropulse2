const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const nodemailer = require('nodemailer');

const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_PATH = process.env.DATABASE_PATH || './users.db';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Dacosta133@';

// Paystack configuration — swap in your live keys when ready
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || '';
const PAYSTACK_ENABLED = Boolean(PAYSTACK_SECRET_KEY && PAYSTACK_SECRET_KEY !== '');

const REFERRAL_TARGET = 7;
const REFERRAL_BONUS_AMOUNT = 50;
const OTP_EXPIRY_MS = 10 * 60 * 1000;
const OTP_RESEND_DELAY_MS = 60 * 1000;
const pendingSignupOtps = new Map();

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Middleware
app.use((req, res, next) => {
  res.setHeader('Bypass-Tunnel-Reminder', 'true');
  next();
});

// Capture raw body for Paystack webhook signature verification before JSON parsing
app.use((req, res, next) => {
  if (req.path === '/api/payment/webhook') {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => { req.rawBody = raw; next(); });
  } else {
    next();
  }
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'agropluse_dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use((req, res, next) => {
  const pathName = String(req.path || '').toLowerCase();
  const isAdminPage = pathName === '/admin' || pathName === '/admin.html';
  const isAdminApi = pathName.startsWith('/api/admin')
    || pathName === '/api/pending'
    || pathName.startsWith('/api/approve/')
    || pathName.startsWith('/api/reject/');

  if (!isAdminPage && !isAdminApi) {
    return next();
  }

  const authHeader = String(req.headers.authorization || '');
  if (!authHeader.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Authentication required');
  }

  try {
    const base64Credentials = authHeader.slice('Basic '.length).trim();
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const separatorIndex = credentials.indexOf(':');
    const username = separatorIndex >= 0 ? credentials.slice(0, separatorIndex) : '';
    const password = separatorIndex >= 0 ? credentials.slice(separatorIndex + 1) : '';

    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
      res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
      return res.status(401).send('Invalid admin credentials');
    }
  } catch (error) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Invalid authentication header');
  }

  next();
});

app.use(express.static(path.join(__dirname)));

// Database setup
const dbDir = path.dirname(DATABASE_PATH);
if (dbDir && dbDir !== '.') {
  fs.mkdirSync(dbDir, { recursive: true });
}
const db = new sqlite3.Database(DATABASE_PATH);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT,
    status TEXT DEFAULT 'approved',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS deposits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id TEXT NOT NULL,
    plan_name TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    payment_provider TEXT,
    payment_reference TEXT,
    mobile_number TEXT,
    approved_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Add mobile_number column if it doesn't exist (for existing databases)
  db.run(`PRAGMA table_info(deposits)`, [], (err, columns) => {
    if (!err && columns && !columns.some(col => col.name === 'mobile_number')) {
      db.run(`ALTER TABLE deposits ADD COLUMN mobile_number TEXT`);
    }
  });

  db.all(`PRAGMA table_info(users)`, [], (err, columns) => {
    if (err) {
      console.error('Error reading users schema:', err);
      return;
    }

    const hasBalance = (columns || []).some((column) => column.name === 'balance');
    const hasReferralCode = (columns || []).some((column) => column.name === 'referral_code');
    const hasReferredBy = (columns || []).some((column) => column.name === 'referred_by');
    const hasReferralBonusUnlocked = (columns || []).some((column) => column.name === 'referral_bonus_unlocked');
    const hasCreatedAt = (columns || []).some((column) => column.name === 'created_at');
    if (!hasBalance) {
      db.run(`ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding users.balance column:', alterErr);
        }
      });
    }

    if (!hasReferralCode) {
      db.run(`ALTER TABLE users ADD COLUMN referral_code TEXT`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding users.referral_code column:', alterErr);
        }
      });
    }

    if (!hasReferredBy) {
      db.run(`ALTER TABLE users ADD COLUMN referred_by INTEGER`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding users.referred_by column:', alterErr);
        }
      });
    }

    if (!hasReferralBonusUnlocked) {
      db.run(`ALTER TABLE users ADD COLUMN referral_bonus_unlocked INTEGER DEFAULT 0`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding users.referral_bonus_unlocked column:', alterErr);
        }
      });
    }

    if (!hasCreatedAt) {
      db.run(`ALTER TABLE users ADD COLUMN created_at TEXT`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding users.created_at column:', alterErr);
          return;
        }
        db.run(`UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at = ''`, (updateErr) => {
          if (updateErr) {
            console.error('Error backfilling users.created_at:', updateErr);
          }
        });
      });
    }
  });

  db.all(`PRAGMA table_info(deposits)`, [], (err, columns) => {
    if (err) {
      console.error('Error reading deposits schema:', err);
      return;
    }

    const allColumns = columns || [];
    const hasStatus = allColumns.some((column) => column.name === 'status');
    const hasPaymentProvider = allColumns.some((column) => column.name === 'payment_provider');
    const hasPaymentReference = allColumns.some((column) => column.name === 'payment_reference');
    const hasApprovedAt = allColumns.some((column) => column.name === 'approved_at');

    if (!hasStatus) {
      db.run(`ALTER TABLE deposits ADD COLUMN status TEXT DEFAULT 'pending'`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding deposits.status column:', alterErr);
        }
      });
    }

    if (!hasPaymentProvider) {
      db.run(`ALTER TABLE deposits ADD COLUMN payment_provider TEXT`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding deposits.payment_provider column:', alterErr);
        }
      });
    }

    if (!hasPaymentReference) {
      db.run(`ALTER TABLE deposits ADD COLUMN payment_reference TEXT`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding deposits.payment_reference column:', alterErr);
        }
      });
    }

    if (!hasApprovedAt) {
      db.run(`ALTER TABLE deposits ADD COLUMN approved_at DATETIME`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding deposits.approved_at column:', alterErr);
        }
      });
    }
  });

  db.all(`SELECT id, phone FROM users WHERE phone IS NOT NULL AND TRIM(phone) <> ''`, [], (scanErr, rows) => {
    if (scanErr) {
      console.error('Error scanning user phone numbers:', scanErr);
      return;
    }

    (rows || []).forEach((row) => {
      const normalizedPhone = normalizePhone(row.phone);
      if (!normalizedPhone || normalizedPhone === String(row.phone)) {
        return;
      }

      db.run(`UPDATE users SET phone = ? WHERE id = ?`, [normalizedPhone, row.id], (updateErr) => {
        if (updateErr) {
          console.error(`Error normalizing phone for user ${row.id}:`, updateErr);
        }
      });
    });
  });
});

const INVESTMENT_PLANS = [
  { id: 'poultry-starter', name: 'Poultry Starter', minDeposit: 20, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'boer-goat', name: 'Boer Goat', minDeposit: 100, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'eggs', name: 'Eggs', minDeposit: 50, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'dairy-cow', name: 'Dairy Cow', minDeposit: 300, payoutMultiplier: 7, payoutDays: 7 }
];

function calculatePlanPayout(amount, plan) {
  const projectedPayout = Math.round((amount * plan.payoutMultiplier) * 100) / 100;
  const payoutDate = new Date(Date.now() + (plan.payoutDays * 24 * 60 * 60 * 1000)).toISOString();
  return {
    projectedPayout,
    payoutMultiplier: plan.payoutMultiplier,
    payoutDays: plan.payoutDays,
    payoutDate
  };
}

function getElapsedDays(fromDate) {
  if (!fromDate) {
    return 0;
  }
  const start = new Date(fromDate);
  if (Number.isNaN(start.getTime())) {
    return 0;
  }
  const now = Date.now();
  const diffMs = Math.max(0, now - start.getTime());
  return Math.floor(diffMs / (24 * 60 * 60 * 1000));
}

function calculateDepositProgress(amount, plan, approvedAt) {
  const principal = Math.round(Number(amount || 0) * 100) / 100;
  const projectedPayout = Math.round((principal * Number(plan.payoutMultiplier || 1)) * 100) / 100;

  if (!approvedAt) {
    return {
      principal,
      projectedPayout,
      currentValue: principal,
      elapsedDays: 0,
      progressPercent: 0,
      isMatured: false
    };
  }

  const elapsedDays = Math.min(getElapsedDays(approvedAt), Number(plan.payoutDays || 0));
  const payoutDays = Math.max(1, Number(plan.payoutDays || 1));
  const growthPerDay = (Number(plan.payoutMultiplier || 1) - 1) / payoutDays;
  const computedValue = principal * (1 + (growthPerDay * elapsedDays));
  const currentValue = Math.round(Math.min(projectedPayout, computedValue) * 100) / 100;

  return {
    principal,
    projectedPayout,
    currentValue,
    elapsedDays,
    progressPercent: Math.min(100, Math.round((elapsedDays / payoutDays) * 100)),
    isMatured: elapsedDays >= payoutDays
  };
}

function calculateUserPortfolio(userId, callback) {
  db.all(
    `SELECT amount, plan_id, approved_at
     FROM deposits
     WHERE user_id = ? AND status = 'approved'`,
    [userId],
    (err, rows) => {
      if (err) {
        return callback(err);
      }

      const totals = (rows || []).reduce((acc, deposit) => {
        const plan = INVESTMENT_PLANS.find((item) => item.id === deposit.plan_id);
        if (!plan) {
          return acc;
        }

        const progress = calculateDepositProgress(deposit.amount, plan, deposit.approved_at);
        acc.portfolioValue += progress.currentValue;
        acc.principalInvested += progress.principal;
        acc.activeDeposits += progress.isMatured ? 0 : 1;
        acc.maturedDeposits += progress.isMatured ? 1 : 0;
        return acc;
      }, {
        portfolioValue: 0,
        principalInvested: 0,
        activeDeposits: 0,
        maturedDeposits: 0
      });

      callback(null, {
        portfolioValue: Math.round(totals.portfolioValue * 100) / 100,
        principalInvested: Math.round(totals.principalInvested * 100) / 100,
        activeDeposits: totals.activeDeposits,
        maturedDeposits: totals.maturedDeposits
      });
    }
  );
}

function anonymizeName(fullName) {
  const safeName = String(fullName || '').trim();
  if (!safeName) {
    return 'Anonymous Investor';
  }

  const parts = safeName.split(/\s+/).filter(Boolean);
  const first = parts[0] || '';
  const last = parts.length > 1 ? parts[parts.length - 1] : '';

  const firstMasked = first.length <= 1
    ? `${first}***`
    : `${first[0]}${'*'.repeat(Math.max(2, first.length - 1))}`;
  const lastInitial = last ? ` ${last[0]}.` : '';

  return `${firstMasked}${lastInitial}`;
}

function generateReferralCode(name, userId) {
  const seedName = String(name || 'agro').replace(/[^a-zA-Z]/g, '').toUpperCase();
  const prefix = (seedName.slice(0, 4) || 'AGRO').padEnd(4, 'X');
  const suffix = String(userId || '').padStart(4, '0');
  const randomPart = crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${prefix}${suffix}${randomPart}`;
}

function getReferralStats(userId, callback) {
  db.get(
    `SELECT id, referral_code, referred_by, referral_bonus_unlocked
     FROM users
     WHERE id = ?`,
    [userId],
    (userErr, userRow) => {
      if (userErr) {
        return callback(userErr);
      }

      if (!userRow) {
        return callback(null, null);
      }

      db.get(
        `SELECT COUNT(*) AS total_referrals
         FROM users
         WHERE referred_by = ?`,
        [userId],
        (countErr, countRow) => {
          if (countErr) {
            return callback(countErr);
          }

          const totalReferrals = Number((countRow && countRow.total_referrals) || 0);
          const bonusEligible = totalReferrals >= REFERRAL_TARGET;
          const bonusUnlocked = bonusEligible || Number(userRow.referral_bonus_unlocked || 0) === 1;

          if (bonusEligible && Number(userRow.referral_bonus_unlocked || 0) !== 1) {
            db.run(
              `UPDATE users SET referral_bonus_unlocked = 1 WHERE id = ?`,
              [userId],
              (updateErr) => {
                if (updateErr) {
                  console.error('Error unlocking referral bonus:', updateErr);
                }
              }
            );
          }

          callback(null, {
            referralCode: userRow.referral_code || '',
            referredBy: userRow.referred_by || null,
            totalReferrals,
            target: REFERRAL_TARGET,
            remaining: Math.max(0, REFERRAL_TARGET - totalReferrals),
            bonusUnlocked,
            bonusAmount: REFERRAL_BONUS_AMOUNT
          });
        }
      );
    }
  );
}

function requireAuth(req, res, next) {
  if (!req.session.user || !req.session.user.id) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  next();
}

function parseBasicAuthorization(headerValue) {
  const raw = String(headerValue || '');
  if (!raw.startsWith('Basic ')) {
    return null;
  }

  const encoded = raw.slice(6).trim();
  if (!encoded) {
    return null;
  }

  try {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const separatorIndex = decoded.indexOf(':');
    if (separatorIndex === -1) {
      return null;
    }

    return {
      username: decoded.slice(0, separatorIndex),
      password: decoded.slice(separatorIndex + 1)
    };
  } catch (error) {
    return null;
  }
}

function requireAdminAccess(req, res, next) {
  const credentials = parseBasicAuthorization(req.headers.authorization);
  const valid = credentials
    && credentials.username === ADMIN_USERNAME
    && credentials.password === ADMIN_PASSWORD;

  if (valid) {
    return next();
  }

  res.setHeader('WWW-Authenticate', 'Basic realm="Agro Pluse Admin"');
  const wantsJson = String(req.path || '').toLowerCase().startsWith('/api/');
  if (wantsJson) {
    return res.status(401).json({ success: false, message: 'Admin authentication required' });
  }

  return res.status(401).send('Admin authentication required.');
}

function getEmailTransporter() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });
}

async function sendSignupOtpEmail({ email, name, otpCode }) {
  const transporter = getEmailTransporter();
  
  if (!transporter) {
    // Test mode: log the OTP for development/testing
    console.warn(`🔐 TEST MODE: OTP for ${email} is: ${otpCode}`);
    return { testMode: true, otpCode };
  }

  const fromEmail = process.env.FROM_EMAIL || process.env.SMTP_USER;
  await transporter.sendMail({
    from: fromEmail,
    to: email,
    subject: 'Your Agro Pluse verification code',
    text: `Hello ${name}, your Agro Pluse verification code is ${otpCode}. It expires in 10 minutes.`,
    html: `<p>Hello ${name},</p><p>Your Agro Pluse verification code is:</p><h2 style="letter-spacing: 2px;">${otpCode}</h2><p>This code expires in 10 minutes.</p>`
  });
  
  return { testMode: false };
}

async function sendWelcomeEmail({ email, name }) {
  const transporter = getEmailTransporter();
  if (!transporter) {
    return;
  }

  const fromEmail = process.env.FROM_EMAIL || process.env.SMTP_USER;
  await transporter.sendMail({
    from: fromEmail,
    to: email,
    subject: 'Welcome to Agro Pluse',
    text: `Welcome ${name}! Your Agro Pluse account has been created successfully. You can now log in and start investing.`,
    html: `<p>Welcome <strong>${name}</strong>!</p><p>Your Agro Pluse account has been created successfully.</p><p>You can now log in and start investing.</p>`
  });
}

async function sendDepositStatusEmail({ email, name, status, amount, planName, reference }) {
  const transporter = getEmailTransporter();
  if (!transporter) {
    return;
  }

  const approved = String(status || '').toLowerCase() === 'approved';
  const fromEmail = process.env.FROM_EMAIL || process.env.SMTP_USER;
  const formattedAmount = `GH₵ ${Number(amount || 0).toFixed(2)}`;
  const subject = approved
    ? 'Deposit Approved - Agro Pluse'
    : 'Deposit Update - Agro Pluse';

  const text = approved
    ? `Hello ${name}, your deposit for ${planName} (${formattedAmount}) has been approved and is now active. Reference: ${reference || 'N/A'}.`
    : `Hello ${name}, your deposit for ${planName} (${formattedAmount}) was not approved. Reference: ${reference || 'N/A'}. Please contact support for assistance.`;

  const html = approved
    ? `<p>Hello ${name},</p><p>Your deposit for <strong>${planName}</strong> (${formattedAmount}) has been <strong>approved</strong> and is now active.</p><p>Reference: <strong>${reference || 'N/A'}</strong></p>`
    : `<p>Hello ${name},</p><p>Your deposit for <strong>${planName}</strong> (${formattedAmount}) was <strong>not approved</strong>.</p><p>Reference: <strong>${reference || 'N/A'}</strong></p><p>Please contact support for assistance.</p>`;

  await transporter.sendMail({
    from: fromEmail,
    to: email,
    subject,
    text,
    html
  });
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function normalizePhone(phone) {
  const digitsOnly = String(phone || '').replace(/\D/g, '');

  if (!digitsOnly) {
    return '';
  }

  if (digitsOnly.startsWith('233') && digitsOnly.length === 12) {
    return `0${digitsOnly.slice(3)}`;
  }

  if (digitsOnly.length === 9) {
    return `0${digitsOnly}`;
  }

  return digitsOnly;
}

function getPhoneLookupVariants(phoneInput) {
  const digitsOnly = String(phoneInput || '').replace(/\D/g, '');
  const normalized = normalizePhone(digitsOnly);
  const variants = new Set();

  if (digitsOnly) {
    variants.add(digitsOnly);
  }

  if (normalized) {
    variants.add(normalized);
  }

  if (normalized && normalized.startsWith('0') && normalized.length === 10) {
    variants.add(`233${normalized.slice(1)}`);
  }

  if (digitsOnly.startsWith('233') && digitsOnly.length === 12) {
    variants.add(`0${digitsOnly.slice(3)}`);
  }

  const list = Array.from(variants).filter(Boolean);
  while (list.length < 3) {
    list.push('');
  }

  return list.slice(0, 3);
}

function generateOtpCode() {
  return String(Math.floor(100000 + (Math.random() * 900000)));
}

function clearExpiredSignupOtps() {
  const now = Date.now();
  pendingSignupOtps.forEach((entry, email) => {
    if (!entry || entry.expiresAt <= now) {
      pendingSignupOtps.delete(email);
    }
  });
}

function validateReferrer(referralCode, callback) {
  const cleanedReferralCode = String(referralCode || '').trim().toUpperCase();
  if (!cleanedReferralCode) {
    return callback(null, null);
  }

  db.get(
    `SELECT id FROM users WHERE UPPER(referral_code) = ?`,
    [cleanedReferralCode],
    (findErr, referrerRow) => {
      if (findErr) {
        return callback(findErr);
      }
      if (!referrerRow) {
        return callback(null, 'INVALID_REFERRAL');
      }
      callback(null, referrerRow.id);
    }
  );
}

function createUserAccount({ name, email, phone, hashedPassword, referrerId }, req, res) {
  db.run(
    `INSERT INTO users (name, email, phone, password, status, referred_by, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
    [name, email, phone, hashedPassword, 'approved', referrerId || null],
    function(err) {
      if (err) {
        console.error('Signup error:', err);
        return res.json({ success: false, message: 'Email already exists' });
      }

      const newUserId = this.lastID;
      const ownReferralCode = generateReferralCode(name, newUserId);

      db.run(
        `UPDATE users SET referral_code = ? WHERE id = ?`,
        [ownReferralCode, newUserId],
        (updateErr) => {
          if (updateErr) {
            console.error('Error setting referral code:', updateErr);
          }

          req.session.user = {
            id: newUserId,
            name,
            email,
            phone,
            balance: 0
          };

          res.json({
            success: true,
            message: 'Signup successful',
            user: req.session.user,
            referral: {
              referralCode: ownReferralCode,
              referredBy: referrerId || null
            }
          });

          sendWelcomeEmail({ email, name }).catch((mailErr) => {
            console.error('Welcome email error:', mailErr);
          });
        }
      );
    }
  );
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'home.html'));
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signup', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/website', (req, res) => {
  res.sendFile(path.join(__dirname, 'website.html'));
});

// Helper: Hash password
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function isStrongPassword(password) {
  return /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(String(password || ''));
}

// API Routes
app.post('/api/signup', (req, res) => {
  const { name, email, phone, password, referralCode } = req.body;
  const normalizedEmail = normalizeEmail(email);
  const normalizedPhone = normalizePhone(phone);
  const [phoneVariant1, phoneVariant2, phoneVariant3] = getPhoneLookupVariants(phone);

  if (!name || !normalizedEmail || !normalizedPhone || !password) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      success: false,
      message: 'Password must be at least 8 characters and include 1 uppercase letter, 1 number, and 1 symbol.'
    });
  }

  db.get(
    `SELECT id,
            CASE
              WHEN LOWER(email) = ? THEN 'email'
              WHEN phone IN (?, ?, ?) THEN 'phone'
              ELSE 'unknown'
            END AS duplicate_type
     FROM users
     WHERE LOWER(email) = ? OR phone IN (?, ?, ?)
     LIMIT 1`,
    [normalizedEmail, phoneVariant1, phoneVariant2, phoneVariant3, normalizedEmail, phoneVariant1, phoneVariant2, phoneVariant3],
    (emailErr, row) => {
    if (emailErr) {
      console.error('Signup email check error:', emailErr);
      return res.status(500).json({ success: false, message: 'Server error' });
    }

    if (row) {
      if (row.duplicate_type === 'phone') {
        return res.status(400).json({ success: false, message: 'Phone number already exists' });
      }
      return res.status(400).json({ success: false, message: 'Email already exists' });
    }

    validateReferrer(referralCode, (refErr, refResult) => {
      if (refErr) {
        console.error('Referral lookup error:', refErr);
        return res.status(500).json({ success: false, message: 'Server error' });
      }

      if (refResult === 'INVALID_REFERRAL') {
        return res.status(400).json({ success: false, message: 'Invalid referral code' });
      }

      createUserAccount({
        name: String(name).trim(),
        email: normalizedEmail,
        phone: normalizedPhone,
        hashedPassword: hashPassword(password),
        referrerId: refResult || null
      }, req, res);
    });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const identifier = String(email || '').trim();
  const normalizedEmail = normalizeEmail(identifier);
  const [phoneVariant1, phoneVariant2, phoneVariant3] = getPhoneLookupVariants(identifier);
  const rawPassword = String(password || '');
  const trimmedPassword = rawPassword.trim();
  
  // Validate input
  if (!identifier || !rawPassword) {
    return res.json({ success: false, message: 'Email and password required' });
  }

  const loginWithPassword = (passwordValue, callback) => {
    const hashedPassword = hashPassword(passwordValue);

    db.get(
      `SELECT *
       FROM users
       WHERE (LOWER(email) = ? OR phone IN (?, ?, ?))
         AND password = ?
         AND status = 'approved'`,
      [normalizedEmail, phoneVariant1, phoneVariant2, phoneVariant3, hashedPassword],
      callback
    );
  };

  loginWithPassword(rawPassword, (err, row) => {
      if (err) {
        console.error('Login error:', err);
        return res.json({ success: false, message: 'Server error' });
      }
      if (row) {
        req.session.user = {
          id: row.id,
          name: row.name,
          email: row.email,
          phone: row.phone,
          balance: Number(row.balance || 0)
        };
        return res.json({ success: true, message: 'Login successful', user: req.session.user });
      }

      if (trimmedPassword && trimmedPassword !== rawPassword) {
        return loginWithPassword(trimmedPassword, (retryErr, retryRow) => {
          if (retryErr) {
            console.error('Login retry error:', retryErr);
            return res.json({ success: false, message: 'Server error' });
          }

          if (retryRow) {
            req.session.user = {
              id: retryRow.id,
              name: retryRow.name,
              email: retryRow.email,
              phone: retryRow.phone,
              balance: Number(retryRow.balance || 0)
            };
            return res.json({ success: true, message: 'Login successful', user: req.session.user });
          }

          return res.json({ success: false, message: 'Invalid credentials or not approved' });
        });
      }

      return res.json({ success: false, message: 'Invalid credentials or not approved' });
    });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, authenticated: false });
  }

  db.get(`SELECT id, name, email, phone FROM users WHERE id = ?`, [req.session.user.id], (err, row) => {
    if (err) {
      console.error('Error loading current user:', err);
      return res.status(500).json({ success: false, authenticated: false, message: 'Server error' });
    }

    if (!row) {
      return res.json({ success: false, authenticated: false });
    }

    calculateUserPortfolio(req.session.user.id, (portfolioErr, portfolio) => {
      if (portfolioErr) {
        console.error('Error calculating portfolio:', portfolioErr);
        return res.status(500).json({ success: false, authenticated: false, message: 'Server error' });
      }

      getReferralStats(req.session.user.id, (refErr, referralStats) => {
        if (refErr) {
          console.error('Error loading referral stats:', refErr);
          return res.status(500).json({ success: false, authenticated: false, message: 'Server error' });
        }

        req.session.user = {
          id: row.id,
          name: row.name,
          email: row.email,
          phone: row.phone,
          balance: Number((portfolio && portfolio.portfolioValue) || 0)
        };

        res.json({
          success: true,
          authenticated: true,
          user: req.session.user,
          portfolio: {
            principalInvested: Number((portfolio && portfolio.principalInvested) || 0),
            activeDeposits: Number((portfolio && portfolio.activeDeposits) || 0),
            maturedDeposits: Number((portfolio && portfolio.maturedDeposits) || 0)
          },
          referral: referralStats
        });
      });
    });
  });
});

app.get('/api/referrals', requireAuth, (req, res) => {
  getReferralStats(req.session.user.id, (err, stats) => {
    if (err) {
      console.error('Error loading referrals:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    res.json({ success: true, referral: stats });
  });
});

app.get('/api/admin/referrals', (req, res) => {
  db.all(
    `SELECT u.id, u.name, u.email, u.referral_code,
            COUNT(r.id) AS referrals_count
     FROM users u
     LEFT JOIN users r ON r.referred_by = u.id
     GROUP BY u.id, u.name, u.email, u.referral_code
     HAVING referrals_count > 0
     ORDER BY referrals_count DESC, u.id DESC
     LIMIT 50`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Error loading admin referrals:', err);
        return res.status(500).json({ success: false, message: 'Server error', referrals: [] });
      }
      res.json({ success: true, referrals: rows || [] });
    }
  );
});

app.get('/api/plans', requireAuth, (req, res) => {
  res.json({ success: true, plans: INVESTMENT_PLANS });
});

app.get('/api/deposits', requireAuth, (req, res) => {
  db.all(
    `SELECT id, plan_id, plan_name, amount, status, payment_provider, payment_reference, approved_at, created_at
     FROM deposits
     WHERE user_id = ?
     ORDER BY created_at DESC, id DESC`,
    [req.session.user.id],
    (err, rows) => {
      if (err) {
        console.error('Error loading deposits:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      const depositsWithPayout = (rows || []).map((deposit) => {
        const plan = INVESTMENT_PLANS.find((item) => item.id === deposit.plan_id);
        if (!plan) {
          return deposit;
        }

        const progress = calculateDepositProgress(deposit.amount, plan, deposit.approved_at);
        const payoutDueAt = deposit.approved_at
          ? new Date(new Date(deposit.approved_at).getTime() + (plan.payoutDays * 24 * 60 * 60 * 1000)).toISOString()
          : null;

        return {
          ...deposit,
          payout_multiplier: plan.payoutMultiplier,
          payout_days: plan.payoutDays,
          projected_payout: progress.projectedPayout,
          current_value: progress.currentValue,
          elapsed_days: progress.elapsedDays,
          progress_percent: progress.progressPercent,
          is_matured: progress.isMatured,
          payout_due_at: payoutDueAt
        };
      });

      res.json({ success: true, deposits: depositsWithPayout });
    }
  );
});

app.get('/api/recent-activity', (req, res) => {
  db.all(
    `SELECT u.name AS user_name, d.plan_name, d.amount, d.plan_id, d.created_at
     FROM deposits d
     INNER JOIN users u ON u.id = d.user_id
     WHERE d.status = 'approved'
     ORDER BY d.created_at DESC, d.id DESC
     LIMIT 8`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Error loading recent activity:', err);
        return res.status(500).json({ success: false, message: 'Server error', activity: [] });
      }

      const activity = (rows || []).map((item) => {
        const plan = INVESTMENT_PLANS.find((planItem) => planItem.id === item.plan_id);
        const multiplier = Number((plan && plan.payoutMultiplier) || 7);
        const amount = Number(item.amount || 0);
        return {
          investor: anonymizeName(item.user_name),
          planName: item.plan_name,
          amount,
          projectedPayout: Math.round((amount * multiplier) * 100) / 100,
          createdAt: item.created_at
        };
      });

      res.json({ success: true, activity });
    }
  );
});

app.post('/api/deposit', requireAuth, (req, res) => {
  const { planId, amount, paymentReference, mobileNumber } = req.body;
  const parsedAmount = Number(amount);

  if (!planId || Number.isNaN(parsedAmount) || parsedAmount <= 0) {
    return res.status(400).json({ success: false, message: 'Valid plan and amount are required' });
  }

  if (!mobileNumber || String(mobileNumber).trim() === '') {
    return res.status(400).json({ success: false, message: 'Mobile number is required' });
  }

  const plan = INVESTMENT_PLANS.find((item) => item.id === planId);
  if (!plan) {
    return res.status(400).json({ success: false, message: 'Invalid investment plan selected' });
  }

  if (parsedAmount < plan.minDeposit) {
    return res.status(400).json({ success: false, message: `Minimum deposit for ${plan.name} is GH₵ ${plan.minDeposit}` });
  }

  const roundedAmount = Math.round(parsedAmount * 100) / 100;
  const provider = 'Manual';
  const reference = String(paymentReference || '').trim();
  const phone = String(mobileNumber).trim();
  const payoutDetails = calculatePlanPayout(roundedAmount, plan);

  db.run(
    `INSERT INTO deposits (user_id, plan_id, plan_name, amount, status, payment_provider, payment_reference, mobile_number) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`,
    [req.session.user.id, plan.id, plan.name, roundedAmount, provider, reference, phone],
    function(insertErr) {
      if (insertErr) {
        console.error('Error creating deposit:', insertErr);
        return res.status(500).json({ success: false, message: 'Failed to create deposit' });
      }

      const depositId = this.lastID;

      res.json({
        success: true,
        message: 'Deposit submitted and pending payment confirmation.',
        deposit: {
          id: depositId,
          planId: plan.id,
          planName: plan.name,
          amount: roundedAmount,
          status: 'pending',
          paymentProvider: provider,
          paymentReference: reference,
          mobileNumber: phone,
          projectedPayout: payoutDetails.projectedPayout,
          payoutMultiplier: payoutDetails.payoutMultiplier,
          payoutDays: payoutDetails.payoutDays,
          payoutDate: payoutDetails.payoutDate
        },
        balance: 0
      });
    }
  );
});

app.get('/api/admin/pending-deposits', (req, res) => {
  db.all(
    `SELECT d.id, d.user_id, d.plan_id, d.plan_name, d.amount, d.status, d.payment_provider, d.payment_reference, d.created_at,
            u.name AS user_name, u.email AS user_email
     FROM deposits d
     INNER JOIN users u ON u.id = d.user_id
     WHERE d.status = 'pending'
     ORDER BY d.created_at DESC, d.id DESC`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Error loading pending deposits:', err);
        return res.status(500).json({ success: false, message: 'Server error', deposits: [] });
      }
      res.json({ success: true, deposits: rows || [] });
    }
  );
});

app.get('/api/admin/users-overview', (req, res) => {
  db.all(
    `SELECT
        u.id,
        u.name,
        u.email,
        u.phone,
        u.status,
        u.created_at,
        COUNT(d.id) AS deposit_count,
        COALESCE(SUM(d.amount), 0) AS total_deposited,
        COALESCE(SUM(CASE WHEN d.status = 'approved' THEN d.amount ELSE 0 END), 0) AS approved_total_deposited,
        COALESCE(SUM(CASE WHEN d.status = 'pending' THEN d.amount ELSE 0 END), 0) AS pending_total_deposited,
        MAX(d.created_at) AS last_deposit_at
     FROM users u
     LEFT JOIN deposits d ON d.user_id = u.id
     GROUP BY u.id, u.name, u.email, u.phone, u.status, u.created_at
     ORDER BY u.id DESC`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Error loading admin users overview:', err);
        return res.status(500).json({ success: false, message: 'Server error', users: [] });
      }
      res.json({ success: true, users: rows || [] });
    }
  );
});

app.post('/api/admin/approve-deposit/:id', (req, res) => {
  const depositId = Number(req.params.id);
  if (!depositId) {
    return res.status(400).json({ success: false, message: 'Invalid deposit id' });
  }

  db.run(
    `UPDATE deposits
     SET status = 'approved', approved_at = CURRENT_TIMESTAMP
     WHERE id = ? AND status = 'pending'`,
    [depositId],
    function(err) {
      if (err) {
        console.error('Error approving deposit:', err);
        return res.status(500).json({ success: false, message: 'Failed to approve deposit' });
      }

      if (!this.changes) {
        return res.status(404).json({ success: false, message: 'Pending deposit not found' });
      }

      res.json({ success: true, message: 'Deposit approved successfully' });

      db.get(
        `SELECT d.amount, d.plan_name, d.payment_reference, u.email AS user_email, u.name AS user_name
         FROM deposits d
         INNER JOIN users u ON u.id = d.user_id
         WHERE d.id = ?`,
        [depositId],
        (rowErr, row) => {
          if (rowErr || !row) {
            if (rowErr) {
              console.error('Error loading approved deposit email details:', rowErr);
            }
            return;
          }

          sendDepositStatusEmail({
            email: row.user_email,
            name: row.user_name,
            status: 'approved',
            amount: row.amount,
            planName: row.plan_name,
            reference: row.payment_reference
          }).catch((mailErr) => {
            console.error('Approved deposit email error:', mailErr);
          });
        }
      );
    }
  );
});

app.post('/api/admin/reject-deposit/:id', (req, res) => {
  const depositId = Number(req.params.id);
  if (!depositId) {
    return res.status(400).json({ success: false, message: 'Invalid deposit id' });
  }

  db.run(
    `UPDATE deposits
     SET status = 'rejected'
     WHERE id = ? AND status = 'pending'`,
    [depositId],
    function(err) {
      if (err) {
        console.error('Error rejecting deposit:', err);
        return res.status(500).json({ success: false, message: 'Failed to reject deposit' });
      }

      if (!this.changes) {
        return res.status(404).json({ success: false, message: 'Pending deposit not found' });
      }

      res.json({ success: true, message: 'Deposit rejected' });

      db.get(
        `SELECT d.amount, d.plan_name, d.payment_reference, u.email AS user_email, u.name AS user_name
         FROM deposits d
         INNER JOIN users u ON u.id = d.user_id
         WHERE d.id = ?`,
        [depositId],
        (rowErr, row) => {
          if (rowErr || !row) {
            if (rowErr) {
              console.error('Error loading rejected deposit email details:', rowErr);
            }
            return;
          }

          sendDepositStatusEmail({
            email: row.user_email,
            name: row.user_name,
            status: 'rejected',
            amount: row.amount,
            planName: row.plan_name,
            reference: row.payment_reference
          }).catch((mailErr) => {
            console.error('Rejected deposit email error:', mailErr);
          });
        }
      );
    }
  );
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.json({ success: false, message: 'Failed to logout' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

app.get('/api/pending', (req, res) => {
  db.all(`SELECT id, name, email, phone, status FROM users WHERE status = 'pending'`, [], (err, rows) => {
    if (err) {
      console.error('Error fetching pending users:', err);
      return res.json({ success: false, message: 'Server error', users: [] });
    }
    res.json({ success: true, users: rows || [] });
  });
});

// ─── Paystack helpers ──────────────────────────────────────────────────────────

function paystackRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'api.paystack.co',
      path,
      method,
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    };
    const req = https.request(options, (res2) => {
      let data = '';
      res2.on('data', chunk => { data += chunk; });
      res2.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Invalid JSON from Paystack')); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// Map our network IDs to Paystack's Ghana MoMo provider codes
const PAYSTACK_NETWORK_MAP = {
  mtn: 'mtn',
  telecel: 'vod',
  airteltigo: 'tigo'
};

// ─── Expose Paystack public key to frontend ────────────────────────────────────

app.get('/api/payment/config', (req, res) => {
  res.json({ paystackEnabled: PAYSTACK_ENABLED, publicKey: PAYSTACK_PUBLIC_KEY });
});

// ─── Initiate a Paystack mobile money charge ───────────────────────────────────

app.post('/api/payment/initiate', requireAuth, (req, res) => {
  if (!PAYSTACK_ENABLED) {
    return res.status(503).json({ success: false, message: 'Online payment is not yet active. Please try again later.' });
  }

  const { planId, amount, mobileNumber, network } = req.body;
  const parsedAmount = Number(amount);

  if (!planId || isNaN(parsedAmount) || parsedAmount <= 0) {
    return res.status(400).json({ success: false, message: 'Valid plan and amount are required.' });
  }
  if (!mobileNumber || String(mobileNumber).trim().length < 10) {
    return res.status(400).json({ success: false, message: 'A valid mobile number is required.' });
  }
  const paystackProvider = PAYSTACK_NETWORK_MAP[network];
  if (!paystackProvider) {
    return res.status(400).json({ success: false, message: 'Please select a valid network.' });
  }

  const plan = INVESTMENT_PLANS.find(p => p.id === planId);
  if (!plan) {
    return res.status(400).json({ success: false, message: 'Invalid investment plan selected.' });
  }
  if (parsedAmount < plan.minDeposit) {
    return res.status(400).json({ success: false, message: `Minimum deposit for ${plan.name} is GH₵ ${plan.minDeposit}.` });
  }

  const roundedAmount = Math.round(parsedAmount * 100) / 100;
  const amountInPesewas = Math.round(roundedAmount * 100); // Paystack needs pesewas
  const phone = String(mobileNumber).trim();
  const userEmail = req.session.user.email;
  const userId = req.session.user.id;

  // First create a pending deposit, then charge via Paystack
  db.run(
    `INSERT INTO deposits (user_id, plan_id, plan_name, amount, status, payment_provider, mobile_number)
     VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
    [userId, plan.id, plan.name, roundedAmount, `Paystack/${PAYSTACK_NETWORK_MAP[network].toUpperCase()}`, phone],
    function(insertErr) {
      if (insertErr) {
        console.error('Deposit insert error:', insertErr);
        return res.status(500).json({ success: false, message: 'Could not create deposit record.' });
      }

      const depositId = this.lastID;

      paystackRequest('POST', '/charge', {
        email: userEmail,
        amount: amountInPesewas,
        currency: 'GHS',
        mobile_money: { phone, provider: paystackProvider }
      }).then(paystackRes => {
        if (!paystackRes.status) {
          // Paystack rejected — remove pending deposit
          db.run(`DELETE FROM deposits WHERE id = ?`, [depositId]);
          return res.status(400).json({ success: false, message: paystackRes.message || 'Payment initiation failed.' });
        }

        const ref = paystackRes.data.reference;
        // Store reference so webhook can match it later
        db.run(`UPDATE deposits SET payment_reference = ? WHERE id = ?`, [ref, depositId]);

        res.json({
          success: true,
          message: `A payment prompt has been sent to ${phone}. Please approve it on your phone to complete your deposit.`,
          reference: ref,
          depositId
        });
      }).catch(err => {
        console.error('Paystack charge error:', err);
        db.run(`DELETE FROM deposits WHERE id = ?`, [depositId]);
        res.status(500).json({ success: false, message: 'Payment gateway error. Please try again.' });
      });
    }
  );
});

// ─── Paystack webhook — auto-approves deposit on charge.success ────────────────

app.post('/api/payment/webhook', (req, res) => {
  // Verify the webhook came from Paystack
  const signature = req.headers['x-paystack-signature'];
  const expectedSig = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(req.rawBody || '')
    .digest('hex');

  if (signature !== expectedSig) {
    return res.status(401).send('Invalid signature');
  }

  res.sendStatus(200); // Acknowledge immediately

  let event;
  try { event = JSON.parse(req.rawBody); } catch (e) { return; }

  if (event.event !== 'charge.success') return;

  const ref = event.data && event.data.reference;
  if (!ref) return;

  db.get(
    `SELECT d.id, d.user_id, d.plan_name, d.amount, d.payment_reference,
            u.email AS user_email, u.name AS user_name
     FROM deposits d
     INNER JOIN users u ON u.id = d.user_id
     WHERE d.payment_reference = ? AND d.status = 'pending'`,
    [ref],
    (err, deposit) => {
      if (err || !deposit) return;

      db.run(
        `UPDATE deposits SET status = 'approved', approved_at = CURRENT_TIMESTAMP WHERE id = ?`,
        [deposit.id],
        (updateErr) => {
          if (updateErr) {
            console.error('Webhook deposit approve error:', updateErr);
            return;
          }
          sendDepositStatusEmail({
            email: deposit.user_email,
            name: deposit.user_name,
            status: 'approved',
            amount: deposit.amount,
            planName: deposit.plan_name,
            reference: deposit.payment_reference
          }).catch(e => console.error('Webhook email error:', e));
        }
      );
    }
  );
});

// ──────────────────────────────────────────────────────────────────────────────

app.post('/api/approve/:id', (req, res) => {
  const id = req.params.id;
  db.run(`UPDATE users SET status = 'approved' WHERE id = ?`, [id], function(err) {
    if (err) {
      console.error('Error approving user:', err);
      return res.json({ success: false, message: 'Error approving user' });
    }
    res.json({ success: true, message: 'User approved' });
  });
});

app.post('/api/reject/:id', (req, res) => {
  const id = req.params.id;
  db.run(`DELETE FROM users WHERE id = ?`, [id], function(err) {
    if (err) {
      console.error('Error rejecting user:', err);
      return res.json({ success: false, message: 'Error rejecting user' });
    }
    res.json({ success: true, message: 'User rejected' });
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});