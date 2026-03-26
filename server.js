const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const nodemailer = require('nodemailer');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_PATH = process.env.DATABASE_PATH || './users.db';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// PAYSTACK WEBHOOK HANDLER
app.post('/api/payment/webhook', (req, res) => {
  // Paystack sends events as JSON
  const event = req.body;
  // For extra security, you can verify the signature here (optional, not shown for brevity)
  if (event && event.event === 'charge.success' && event.data && event.data.status === 'success') {
    const reference = event.data.reference;
    const amount = event.data.amount / 100; // Convert from kobo/pesewas
    const email = event.data.customer.email;
    const plan = (event.data.metadata && event.data.metadata.custom_fields && event.data.metadata.custom_fields.find(f => f.variable_name === 'plan')) ? event.data.metadata.custom_fields.find(f => f.variable_name === 'plan').value : null;
    const mobileNumber = (event.data.metadata && event.data.metadata.custom_fields && event.data.metadata.custom_fields.find(f => f.variable_name === 'momo_number')) ? event.data.metadata.custom_fields.find(f => f.variable_name === 'momo_number').value : null;
    if (reference && plan && amount && mobileNumber) {
      // Find user by email
      db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) {
          console.error('Webhook: User not found for email', email);
          return res.status(200).send('ok');
        }
        // Check if deposit already exists for this reference
        db.get('SELECT id FROM deposits WHERE payment_reference = ?', [reference], (findErr, deposit) => {
          if (findErr) return res.status(200).send('ok');
          if (deposit) return res.status(200).send('ok'); // Already credited
          // Credit user wallet (create deposit)
          const planObj = INVESTMENT_PLANS.find((item) => item.id === plan);
          if (!planObj) return res.status(200).send('ok');
          db.run(
            `INSERT INTO deposits (user_id, plan_id, plan_name, amount, status, payment_provider, payment_reference, mobile_number, approved_at) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, CURRENT_TIMESTAMP)`,
            [user.id, planObj.id, planObj.name, amount, 'Paystack', reference, mobileNumber],
            function(insertErr) {
              if (insertErr) {
                console.error('Webhook: Failed to credit deposit', insertErr);
              }
              return res.status(200).send('ok');
            }
          );
        });
      });
    } else {
      return res.status(200).send('ok');
    }
  } else {
    return res.status(200).send('ok');
  }
});
// PAYSTACK PAYMENT VERIFICATION ENDPOINT
const axios = require('axios');

// Verify Paystack payment by reference
app.post('/api/payment/verify', async (req, res) => {
  const { reference, planId, amount, mobileNumber } = req.body;
  if (!reference || !planId || !amount || !mobileNumber) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }
  if (!PAYSTACK_SECRET_KEY) {
    return res.status(500).json({ success: false, message: 'Paystack secret key not configured.' });
  }
  try {
    const response = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const data = response.data;
    if (data.status && data.data && data.data.status === 'success') {
      // Extra check: verify amount matches
      const paidAmount = Number(data.data.amount) / 100;
      if (Math.abs(paidAmount - Number(amount)) > 0.01) {
        return res.status(400).json({ success: false, message: 'Payment amount mismatch.' });
      }
      // Prevent duplicate deposit for same reference
      db.get('SELECT id FROM deposits WHERE payment_reference = ?', [reference], (findErr, deposit) => {
        if (findErr) {
          console.error('Error checking for duplicate deposit:', findErr);
          return res.status(500).json({ success: false, message: 'Server error.' });
        }
        if (deposit) {
          return res.status(400).json({ success: false, message: 'Payment already recorded.' });
        }
        const plan = INVESTMENT_PLANS.find((item) => item.id === planId);
        if (!plan) {
          return res.status(400).json({ success: false, message: 'Invalid plan.' });
        }
        const roundedAmount = Math.round(Number(amount) * 100) / 100;
        db.run(
          `INSERT INTO deposits (user_id, plan_id, plan_name, amount, status, payment_provider, payment_reference, mobile_number, approved_at) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, CURRENT_TIMESTAMP)`,
          [req.session.user.id, plan.id, plan.name, roundedAmount, 'Paystack', reference, mobileNumber],
          function(insertErr) {
            if (insertErr) {
              console.error('Error creating deposit after Paystack verification:', insertErr);
              return res.status(500).json({ success: false, message: 'Failed to record deposit.' });
            }
            return res.json({ success: true, message: 'Payment verified and deposit recorded.' });
          }
        );
      });
    } else {
      return res.status(400).json({ success: false, message: 'Payment not successful.' });
    }
  } catch (error) {
    console.error('Paystack verification error:', error.message);
    return res.status(500).json({ success: false, message: 'Verification failed.' });
  }
});
// ...existing code...
const SESSION_SECRET = process.env.SESSION_SECRET || (!IS_PRODUCTION ? 'agropluse_dev_secret_change_me' : '');
const KNOWN_INSECURE_ADMIN_USERNAME = 'mercedes133';
const KNOWN_INSECURE_ADMIN_PASSWORD = 'Dacosta133@';
function isUnsetEnvValue(value) {
  const normalized = String(value || '').trim().toUpperCase();
  return !normalized || normalized === 'CHANGE_ME' || normalized === 'CHANGEME' || normalized === 'TODO';
}

function readConfiguredEnvValue(key) {
  const raw = process.env[key];
  return isUnsetEnvValue(raw) ? '' : String(raw).trim();
}

const ADMIN_USERNAME = readConfiguredEnvValue('ADMIN_USERNAME');
const ADMIN_PASSWORD = readConfiguredEnvValue('ADMIN_PASSWORD');
const ADMIN_CONFIGURED = Boolean(ADMIN_USERNAME && ADMIN_PASSWORD);
const ADMIN_USING_DEFAULTS = ADMIN_USERNAME === KNOWN_INSECURE_ADMIN_USERNAME && ADMIN_PASSWORD === KNOWN_INSECURE_ADMIN_PASSWORD;

// Paystack configuration — swap in your live keys when ready
const PAYSTACK_SECRET_KEY = readConfiguredEnvValue('PAYSTACK_SECRET_KEY');
const PAYSTACK_PUBLIC_KEY = readConfiguredEnvValue('PAYSTACK_PUBLIC_KEY');
const PAYSTACK_ENABLED = Boolean(PAYSTACK_SECRET_KEY);

const REFERRAL_TARGET = 7;
const REFERRAL_BONUS_AMOUNT = 50;
const OTP_EXPIRY_MS = 10 * 60 * 1000;
const OTP_RESEND_DELAY_MS = 60 * 1000;
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);
const SESSION_DB_NAME = process.env.SESSION_DB_NAME || 'sessions.db';
const DUPLICATE_IDENTIFIER_MESSAGE = 'This email or phone number has already been used. Please use a different one or log in instead.';
const CHAT_CACHE_TTL_MS = Number(process.env.CHAT_CACHE_TTL_MS || 15000);
const CHAT_DEFAULT_AGENT_NAME = process.env.SUPPORT_AGENT_NAME || 'Support Agent';
const CHAT_ENCRYPTION_SOURCE = String(process.env.CHAT_ENCRYPTION_KEY || SESSION_SECRET || '').trim();
const CHAT_CIPHER_ALGORITHM = 'aes-256-gcm';
const CHAT_FALLBACK_REPLY = 'Thanks for reaching out. I could not fully resolve this yet, so I have routed your chat to human support.';
const pendingSignupOtps = new Map();
const chatMessageCache = new Map();
const chatEncryptionKey = crypto.createHash('sha256').update(CHAT_ENCRYPTION_SOURCE).digest();

function resolveStoragePath(targetPath) {
  if (!targetPath) {
    return __dirname;
  }

  return path.isAbsolute(targetPath) ? targetPath : path.resolve(__dirname, targetPath);
}

const RESOLVED_DATABASE_PATH = resolveStoragePath(DATABASE_PATH);
const DATA_DIRECTORY = path.dirname(RESOLVED_DATABASE_PATH);
const BACKUPS_DIRECTORY = path.join(DATA_DIRECTORY, 'backups');

const LOGS_DIR = path.join(__dirname, 'logs');
const SECURITY_LOG_PATH = path.join(LOGS_DIR, 'security.log');
if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}
if (!fs.existsSync(DATA_DIRECTORY)) {
  fs.mkdirSync(DATA_DIRECTORY, { recursive: true });
}

function runStartupChecks() {
  const errors = [];
  const warnings = [];

  if (!SESSION_SECRET) {
    errors.push('SESSION_SECRET must be configured in production to keep authentication secure across updates.');
  }

  if (IS_PRODUCTION && SESSION_SECRET.length < 32) {
    errors.push('SESSION_SECRET must be at least 32 characters in production.');
  }

  if (BCRYPT_ROUNDS < 10) {
    warnings.push('BCRYPT_ROUNDS is below 10. Increase it to at least 10 for stronger password hashing.');
  }

  if (!ADMIN_CONFIGURED) {
    warnings.push('Admin credentials are not configured. Admin routes will remain disabled until ADMIN_USERNAME and ADMIN_PASSWORD are set.');
  }

  if (ADMIN_USING_DEFAULTS) {
    errors.push('Known insecure admin credentials are configured. Set unique ADMIN_USERNAME and ADMIN_PASSWORD values.');
  }

  if (IS_PRODUCTION && !PAYSTACK_SECRET_KEY) {
    warnings.push('PAYSTACK_SECRET_KEY is not set. Payment initiation endpoints will be unavailable.');
  }

  if (PAYSTACK_PUBLIC_KEY && !PAYSTACK_SECRET_KEY) {
    warnings.push('PAYSTACK_PUBLIC_KEY is configured without PAYSTACK_SECRET_KEY. Configure both keys together.');
  }

  try {
    fs.accessSync(DATA_DIRECTORY, fs.constants.R_OK | fs.constants.W_OK);
  } catch (error) {
    errors.push(`DATA_DIRECTORY is not writable: ${DATA_DIRECTORY}`);
  }

  return { errors, warnings };
}

const startupValidation = runStartupChecks();
startupValidation.warnings.forEach((warning) => {
  console.warn(`[startup-check] ${warning}`);
});
if (startupValidation.errors.length > 0) {
  throw new Error(`[startup-check] ${startupValidation.errors.join(' | ')}`);
}

function backupExistingDatabase() {
  if (!fs.existsSync(RESOLVED_DATABASE_PATH)) {
    return;
  }

  fs.mkdirSync(BACKUPS_DIRECTORY, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[.:]/g, '-');
  const backupPath = path.join(BACKUPS_DIRECTORY, `users-${timestamp}.db`);
  fs.copyFileSync(RESOLVED_DATABASE_PATH, backupPath);

  const backupFiles = fs.readdirSync(BACKUPS_DIRECTORY)
    .filter((fileName) => /^users-.*\.db$/.test(fileName))
    .map((fileName) => ({
      fileName,
      fullPath: path.join(BACKUPS_DIRECTORY, fileName),
      mtimeMs: fs.statSync(path.join(BACKUPS_DIRECTORY, fileName)).mtimeMs
    }))
    .sort((left, right) => right.mtimeMs - left.mtimeMs);

  backupFiles.slice(10).forEach((backupFile) => {
    try {
      fs.unlinkSync(backupFile.fullPath);
    } catch (error) {
      console.error('Failed to prune old database backup:', error.message);
    }
  });
}

backupExistingDatabase();

function encryptChatMessage(plainText) {
  const text = String(plainText || '');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(CHAT_CIPHER_ALGORITHM, chatEncryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${authTag.toString('base64')}.${encrypted.toString('base64')}`;
}

function decryptChatMessage(payload) {
  const raw = String(payload || '');
  if (!raw || !raw.includes('.')) {
    return '';
  }

  const parts = raw.split('.');
  if (parts.length !== 3) {
    return '';
  }

  try {
    const iv = Buffer.from(parts[0], 'base64');
    const authTag = Buffer.from(parts[1], 'base64');
    const ciphertext = Buffer.from(parts[2], 'base64');
    const decipher = crypto.createDecipheriv(CHAT_CIPHER_ALGORITHM, chatEncryptionKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (error) {
    return '';
  }
}

function getChatCacheKey(userId) {
  return `chat:${Number(userId || 0)}`;
}

function getCachedChatMessages(userId) {
  const cacheKey = getChatCacheKey(userId);
  const cached = chatMessageCache.get(cacheKey);
  if (!cached) {
    return null;
  }

  if ((Date.now() - cached.timestamp) > CHAT_CACHE_TTL_MS) {
    chatMessageCache.delete(cacheKey);
    return null;
  }

  return cached.payload;
}

function setCachedChatMessages(userId, payload) {
  const cacheKey = getChatCacheKey(userId);
  chatMessageCache.set(cacheKey, {
    timestamp: Date.now(),
    payload
  });
}

function clearCachedChatMessages(userId) {
  chatMessageCache.delete(getChatCacheKey(userId));
}

function classifyChatIssue(messageText) {
  const message = String(messageText || '').toLowerCase();
  if (!message) return 'general';
  if (/(login|log in|password|account|signin|sign in)/.test(message)) return 'login';
  if (/(pay|payment|momo|mobile money|deposit|reference|charge|paystack)/.test(message)) return 'payment';
  if (/(withdraw|payout|cashout|cash out|matured)/.test(message)) return 'withdrawal';
  if (/(error|bug|issue|problem|fail|failed|not work|cannot|can't)/.test(message)) return 'technical';
  if (/(referral|bonus|invite)/.test(message)) return 'referral';
  return 'general';
}

function shouldEscalateToHuman(messageText) {
  const message = String(messageText || '').toLowerCase();
  if (!message) return false;
  return /(human|agent|person|speak to|talk to|not resolved|still issue|urgent|complaint|angry|scam|fraud|lawsuit)/.test(message);
}

function generateBotReply(messageText) {
  const message = String(messageText || '').toLowerCase();

  if (/(login|log in|password|account locked|can't log|cannot log)/.test(message)) {
    return 'For login issues, confirm your email/phone and password exactly as registered. If it still fails, tell me the exact error and we will route you to human support.';
  }

  if (/(deposit|payment|momo|mobile money|paystack|reference)/.test(message)) {
    return 'Deposits activate automatically after successful payment confirmation. If your prompt failed or no confirmation appears, share your payment reference and mobile number for manual review.';
  }

  if (/(withdraw|payout|cashout|cash out)/.test(message)) {
    return 'Withdrawals are requested from your dashboard once the 7-day period is complete. A human admin confirms manual payout after reviewing your request details.';
  }

  if (/(how long|when|7 day|seven day|mature)/.test(message)) {
    return 'Each plan matures in 7 days from approval time. You can track progress in your dashboard deposit history.';
  }

  if (/(hello|hi|hey)/.test(message)) {
    return 'Hello! I can help with login, deposits, withdrawal timing, and payment checks. Tell me what you need.';
  }

  return CHAT_FALLBACK_REPLY;
}

function getSupportAvailability(callback) {
  db.get(
    `SELECT setting_value FROM support_settings WHERE setting_key = 'agent_online'`,
    [],
    (err, row) => {
      if (err) {
        return callback(err);
      }
      const isOnline = row ? Number(row.setting_value || 0) === 1 : false;
      callback(null, isOnline);
    }
  );
}

function ensureChatConversation(userId, callback) {
  db.get(
    `SELECT c.id, c.user_id, c.status, c.assigned_agent, c.last_user_message_at, c.last_agent_message_at,
            c.last_message_at, c.created_at, c.updated_at,
            u.email AS user_email, u.phone AS user_phone, u.name AS user_name
     FROM chat_conversations c
     INNER JOIN users u ON u.id = c.user_id
     WHERE c.user_id = ?`,
    [userId],
    (findErr, row) => {
      if (findErr) {
        return callback(findErr);
      }

      if (row) {
        const identifier = String(row.user_email || row.user_phone || '').trim();
        return callback(null, { ...row, user_identifier: identifier });
      }

      db.get(`SELECT id, email, phone, name FROM users WHERE id = ?`, [userId], (userErr, userRow) => {
        if (userErr) {
          return callback(userErr);
        }

        if (!userRow) {
          return callback(new Error('User not found for chat.'));
        }

        const identifier = String(userRow.email || userRow.phone || '').trim();
        db.run(
          `INSERT INTO chat_conversations (user_id, user_identifier, status, assigned_agent, last_message_at)
           VALUES (?, ?, 'bot', NULL, CURRENT_TIMESTAMP)`,
          [userId, identifier],
          function(insertErr) {
            if (insertErr) {
              return callback(insertErr);
            }

            callback(null, {
              id: this.lastID,
              user_id: userId,
              status: 'bot',
              assigned_agent: null,
              user_email: userRow.email,
              user_phone: userRow.phone,
              user_name: userRow.name,
              user_identifier: identifier,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            });
          }
        );
      });
    }
  );
}

function insertChatMessage(conversationId, senderType, plaintextMessage, senderName, callback) {
  const encryptedMessage = encryptChatMessage(plaintextMessage);
  db.run(
    `INSERT INTO chat_messages (conversation_id, sender_type, sender_name, encrypted_message)
     VALUES (?, ?, ?, ?)`,
    [conversationId, senderType, senderName || null, encryptedMessage],
    function(insertErr) {
      if (insertErr) {
        return callback(insertErr);
      }

      callback(null, this.lastID);
    }
  );
}

function loadConversationMessages(conversationId, userId, callback) {
  const cached = getCachedChatMessages(userId);
  if (cached && Number(cached.conversationId) === Number(conversationId)) {
    return callback(null, cached.messages);
  }

  db.all(
    `SELECT id, conversation_id, sender_type, sender_name, encrypted_message, created_at
     FROM chat_messages
     WHERE conversation_id = ?
     ORDER BY id ASC`,
    [conversationId],
    (err, rows) => {
      if (err) {
        return callback(err);
      }

      const messages = (rows || []).map((row) => ({
        id: row.id,
        conversationId: row.conversation_id,
        senderType: row.sender_type,
        senderName: row.sender_name,
        message: decryptChatMessage(row.encrypted_message),
        createdAt: row.created_at
      }));

      setCachedChatMessages(userId, {
        conversationId: Number(conversationId),
        messages
      });

      callback(null, messages);
    }
  );
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function getLoginIdentifier(input) {
  const identifier = String(input || '').trim();
  if (!identifier) {
    return 'unknown';
  }

  const normalizedEmail = normalizeEmail(identifier);
  if (normalizedEmail.includes('@')) {
    return normalizedEmail;
  }

  const normalizedPhone = normalizePhone(identifier);
  return normalizedPhone || normalizedEmail || identifier.toLowerCase();
}

function getLoginRateLimitKey(req, identifierOverride) {
  const identifier = getLoginIdentifier(identifierOverride || req.body?.email || '');
  return `${getClientIp(req)}:${identifier}`;
}

function writeSecurityLog(event, req, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    event,
    ip: getClientIp(req),
    path: req.path,
    method: req.method,
    details
  };
  fs.appendFile(SECURITY_LOG_PATH, `${JSON.stringify(entry)}\n`, (err) => {
    if (err) {
      console.error('Failed to write security log:', err.message);
    }
  });
}

function readRecentSecurityLogs(limit = 100) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 100, 500));
  if (!fs.existsSync(SECURITY_LOG_PATH)) {
    return [];
  }

  try {
    const content = fs.readFileSync(SECURITY_LOG_PATH, 'utf8');
    const lines = content.split('\n').map((line) => line.trim()).filter(Boolean);
    const recentLines = lines.slice(-safeLimit);

    return recentLines
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch (error) {
          return null;
        }
      })
      .filter(Boolean)
      .reverse();
  } catch (error) {
    console.error('Failed to read security logs:', error.message);
    return [];
  }
}

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.get('x-forwarded-proto') !== 'https') {
    return res.redirect(`https://${req.get('host')}${req.originalUrl}`);
  }
  return next();
});

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
  store: new SQLiteStore({
    db: SESSION_DB_NAME,
    dir: DATA_DIRECTORY,
    concurrentDB: true
  }),
  name: 'agropluse.sid',
  secret: SESSION_SECRET,
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

  if (!isAdminReady()) {
    writeSecurityLog('admin_not_configured', req, { production: IS_PRODUCTION, usingDefaults: ADMIN_USING_DEFAULTS });
    return res.status(503).send('Admin access is disabled until secure admin credentials are configured.');
  }

  const authHeader = String(req.headers.authorization || '');
  if (!authHeader.startsWith('Basic ')) {
    writeSecurityLog('admin_auth_missing', req);
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Authentication required');
  }

  try {
    const base64Credentials = authHeader.slice('Basic '.length).trim();
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
    const separatorIndex = credentials.indexOf(':');
    const username = separatorIndex >= 0 ? credentials.slice(0, separatorIndex) : '';
    const password = separatorIndex >= 0 ? credentials.slice(separatorIndex + 1) : '';

    if (!isValidAdminCredentials(username, password)) {
      writeSecurityLog('admin_auth_failed', req, { username });
      res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
      return res.status(401).send('Invalid admin credentials');
    }
    writeSecurityLog('admin_auth_success', req, { username });
  } catch (error) {
    writeSecurityLog('admin_auth_header_invalid', req);
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Invalid authentication header');
  }

  next();
});

app.use(express.static(path.join(__dirname)));

// Database setup
const db = new sqlite3.Database(RESOLVED_DATABASE_PATH);

function normalizeExistingUserPhones(callback) {
  db.all(`SELECT id, phone FROM users WHERE phone IS NOT NULL AND TRIM(phone) <> ''`, [], (scanErr, rows) => {
    if (scanErr) {
      console.error('Error scanning user phone numbers:', scanErr);
      return callback();
    }

    const updates = (rows || []).filter((row) => {
      const normalizedPhone = normalizePhone(row.phone);
      return normalizedPhone && normalizedPhone !== String(row.phone);
    });

    if (!updates.length) {
      return callback();
    }

    let pending = updates.length;
    updates.forEach((row) => {
      const normalizedPhone = normalizePhone(row.phone);
      db.run(`UPDATE users SET phone = ? WHERE id = ?`, [normalizedPhone, row.id], (updateErr) => {
        if (updateErr) {
          console.error(`Error normalizing phone for user ${row.id}:`, updateErr);
        }

        pending -= 1;
        if (pending === 0) {
          callback();
        }
      });
    });
  });
}

function reportDuplicateUserIdentifiers() {
  db.all(
    `SELECT 'email' AS field, LOWER(email) AS normalized_value, COUNT(*) AS duplicate_count
     FROM users
     WHERE email IS NOT NULL AND TRIM(email) <> ''
     GROUP BY LOWER(email)
     HAVING COUNT(*) > 1
     UNION ALL
     SELECT 'phone' AS field, phone AS normalized_value, COUNT(*) AS duplicate_count
     FROM users
     WHERE phone IS NOT NULL AND TRIM(phone) <> ''
     GROUP BY phone
     HAVING COUNT(*) > 1`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Error checking duplicate user identifiers:', err);
        return;
      }

      (rows || []).forEach((row) => {
        console.error(`Duplicate user ${row.field} detected for value ${row.normalized_value}. Existing records were preserved and require manual cleanup before strict indexing can be applied.`);
      });
    }
  );
}

function ensureUserIdentityIndexes() {
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_normalized ON users(LOWER(email))`, (emailIndexErr) => {
    if (emailIndexErr) {
      console.error('Failed to enforce unique email identity:', emailIndexErr.message);
    }
  });

  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_normalized ON users(phone) WHERE phone IS NOT NULL AND TRIM(phone) <> ''`, (phoneIndexErr) => {
    if (phoneIndexErr) {
      console.error('Failed to enforce unique phone identity:', phoneIndexErr.message);
    }
  });

  db.run(`CREATE INDEX IF NOT EXISTS idx_users_lookup_email_phone ON users(LOWER(email), phone)`, (lookupIndexErr) => {
    if (lookupIndexErr) {
      console.error('Failed to create user lookup index:', lookupIndexErr.message);
    }
  });
}

db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON`);
  db.run(`PRAGMA busy_timeout = 5000`);
  db.run(`PRAGMA journal_mode = WAL`);

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
    withdrawn_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    success INTEGER DEFAULT 0,
    reason TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS withdrawal_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deposit_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    payout_amount REAL NOT NULL,
    destination_type TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    account_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    note TEXT,
    status TEXT DEFAULT 'pending',
    admin_note TEXT,
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME,
    processed_by TEXT,
    FOREIGN KEY(deposit_id) REFERENCES deposits(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chat_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    user_identifier TEXT NOT NULL,
    status TEXT DEFAULT 'bot',
    assigned_agent TEXT,
    last_user_message_at DATETIME,
    last_agent_message_at DATETIME,
    last_message_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender_type TEXT NOT NULL,
    sender_name TEXT,
    encrypted_message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(conversation_id) REFERENCES chat_conversations(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chat_issue_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    issue_category TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(conversation_id) REFERENCES chat_conversations(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chat_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(conversation_id, user_id),
    FOREIGN KEY(conversation_id) REFERENCES chat_conversations(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS support_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(
    `INSERT INTO support_settings (setting_key, setting_value)
     SELECT 'agent_online', '0'
     WHERE NOT EXISTS (SELECT 1 FROM support_settings WHERE setting_key = 'agent_online')`
  );

  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation_id ON chat_messages(conversation_id, id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_conversations_last_message ON chat_conversations(last_message_at DESC, id DESC)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_issue_events_category ON chat_issue_events(issue_category, created_at DESC)`);

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
    const hasMobileNumber = allColumns.some((column) => column.name === 'mobile_number');
    const hasApprovedAt = allColumns.some((column) => column.name === 'approved_at');
    const hasWithdrawnAt = allColumns.some((column) => column.name === 'withdrawn_at');

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

    if (!hasMobileNumber) {
      db.run(`ALTER TABLE deposits ADD COLUMN mobile_number TEXT`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding deposits.mobile_number column:', alterErr);
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

    if (!hasWithdrawnAt) {
      db.run(`ALTER TABLE deposits ADD COLUMN withdrawn_at DATETIME`, (alterErr) => {
        if (alterErr) {
          console.error('Error adding deposits.withdrawn_at column:', alterErr);
        }
      });
    }
  });

  normalizeExistingUserPhones(() => {
    reportDuplicateUserIdentifiers();
    ensureUserIdentityIndexes();
  });
});

const INVESTMENT_PLANS = [
  { id: 'poultry-starter', name: 'Poultry Starter', minDeposit: 20, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'boer-goat', name: 'Boer Goat', minDeposit: 100, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'eggs', name: 'Eggs', minDeposit: 50, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'dairy-cow', name: 'Dairy Cow', minDeposit: 300, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'maize-farm', name: 'Maize Farm', minDeposit: 150, payoutMultiplier: 7, payoutDays: 7 },
  { id: 'tilapia-pond', name: 'Tilapia Pond', minDeposit: 600, payoutMultiplier: 7, payoutDays: 10 },
  { id: 'catfish-pond', name: 'Catfish Pond', minDeposit: 500, payoutMultiplier: 7, payoutDays: 10 },
  { id: 'piggery-expansion', name: 'Piggery Expansion', minDeposit: 700, payoutMultiplier: 7, payoutDays: 10 },
  { id: 'greenhouse-vegetables', name: 'Greenhouse Vegetables', minDeposit: 1000, payoutMultiplier: 7, payoutDays: 10 }
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

function getPayoutDueAt(approvedAt, payoutDays) {
  if (!approvedAt) {
    return null;
  }

  const approvedDate = new Date(approvedAt);
  if (Number.isNaN(approvedDate.getTime())) {
    return null;
  }

  const safePayoutDays = Math.max(1, Number(payoutDays || 1));
  return new Date(approvedDate.getTime() + (safePayoutDays * 24 * 60 * 60 * 1000));
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
  const payoutMultiplier = Number(plan.payoutMultiplier || 1);
  const payoutDays = Math.max(1, Number(plan.payoutDays || 1));
  const projectedPayout = Math.round((principal * payoutMultiplier) * 100) / 100;
  const dailyIncome = Math.round(((projectedPayout - principal) / payoutDays) * 100) / 100;
  const dueAt = getPayoutDueAt(approvedAt, payoutDays);
  const dueAtIso = dueAt ? dueAt.toISOString() : null;

  if (!approvedAt) {
    return {
      principal,
      projectedPayout,
      dailyIncome,
      currentValue: principal,
      elapsedDays: 0,
      progressPercent: 0,
      isMatured: false,
      payoutDueAt: dueAtIso,
      remainingDays: payoutDays
    };
  }

  const elapsedDays = Math.min(getElapsedDays(approvedAt), payoutDays);
  const growthPerDay = (payoutMultiplier - 1) / payoutDays;
  const computedValue = principal * (1 + (growthPerDay * elapsedDays));
  const currentValue = Math.round(Math.min(projectedPayout, computedValue) * 100) / 100;
  const isMatured = dueAt ? Date.now() >= dueAt.getTime() : elapsedDays >= payoutDays;
  const remainingDays = Math.max(0, payoutDays - elapsedDays);

  return {
    principal,
    projectedPayout,
    dailyIncome,
    currentValue,
    elapsedDays,
    progressPercent: Math.min(100, Math.round((elapsedDays / payoutDays) * 100)),
    isMatured,
    payoutDueAt: dueAtIso,
    remainingDays
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

function isAdminReady() {
  if (!ADMIN_CONFIGURED) {
    return false;
  }

  if (IS_PRODUCTION && ADMIN_USING_DEFAULTS) {
    return false;
  }

  return true;
}

function safeEqualText(left, right) {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function isValidAdminCredentials(username, password) {
  if (!isAdminReady()) {
    return false;
  }

  return safeEqualText(username, ADMIN_USERNAME) && safeEqualText(password, ADMIN_PASSWORD);
}

function requireAdminAccess(req, res, next) {
  if (!isAdminReady()) {
    writeSecurityLog('admin_not_configured', req, { production: IS_PRODUCTION, usingDefaults: ADMIN_USING_DEFAULTS });
    return res.status(503).json({
      success: false,
      message: 'Admin access is disabled until secure admin credentials are configured.'
    });
  }

  const credentials = parseBasicAuthorization(req.headers.authorization);
  const valid = credentials && isValidAdminCredentials(credentials.username, credentials.password);

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
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(400).json({ success: false, message: DUPLICATE_IDENTIFIER_MESSAGE });
        }
        return res.status(500).json({ success: false, message: 'Server error' });
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
  return bcrypt.hashSync(String(password || ''), BCRYPT_ROUNDS);
}

function isBcryptHash(value) {
  return /^\$2[aby]\$\d{2}\$/.test(String(value || ''));
}

function verifyPassword(plainPassword, storedHash) {
  const plain = String(plainPassword || '');
  const stored = String(storedHash || '');

  if (!plain || !stored) {
    return false;
  }

  if (isBcryptHash(stored)) {
    return bcrypt.compareSync(plain, stored);
  }

  const legacyHash = crypto.createHash('sha256').update(plain).digest('hex');
  return legacyHash === stored;
}

function isStrongPassword(password) {
  return /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(String(password || ''));
}

const loginRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => getLoginRateLimitKey(req),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const identifier = String(req.body?.email || '').trim() || 'unknown';
    writeSecurityLog('login_rate_limited', req);
    db.run(
      `INSERT INTO login_history (email, ip_address, success, reason) VALUES (?, ?, ?, ?)`,
      [identifier, getClientIp(req), 0, 'Rate limited after 5 attempts']
    );
    return res.status(429).json({ success: false, message: 'Too many login attempts. Please try again in 10 minutes.' });
  }
});

// API Routes
app.post('/api/signup', (req, res) => {
  const { name, email, phone, password, referralCode } = req.body;
  const normalizedEmail = normalizeEmail(email);
  const normalizedPhone = normalizePhone(phone);
  const [phoneVariant1, phoneVariant2, phoneVariant3] = getPhoneLookupVariants(phone);
  const trimmedPassword = String(password || '').trim(); // ENSURE PASSWORD IS TRIMMED

  if (!name || !normalizedEmail || !normalizedPhone || !trimmedPassword) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  if (!isStrongPassword(trimmedPassword)) {
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
      return res.status(400).json({ success: false, message: DUPLICATE_IDENTIFIER_MESSAGE });
    }

    // Only validate referral if provided, otherwise skip
    if (referralCode && referralCode.trim() !== "") {
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
          hashedPassword: hashPassword(trimmedPassword),
          referrerId: refResult || null
        }, req, res);
      });
    } else {
      createUserAccount({
        name: String(name).trim(),
        email: normalizedEmail,
        phone: normalizedPhone,
        hashedPassword: hashPassword(trimmedPassword),
        referrerId: null
      }, req, res);
    }
  });
});

// Admin API: Get all users
app.get('/api/admin/users', (req, res) => {
  db.all('SELECT id, name, email, phone, created_at, status FROM users ORDER BY created_at DESC', [], (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Failed to fetch users' });
    }
    res.json({ success: true, users: rows });
  });
});

// Admin API: Get login activity
app.get('/api/admin/login-activity', (req, res) => {
  db.all('SELECT id, email, ip_address, success, reason, timestamp FROM login_history ORDER BY timestamp DESC LIMIT 100', [], (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Failed to fetch login activity' });
    }
    res.json({ success: true, logins: rows });
  });
});

app.post('/api/login', loginRateLimiter, (req, res) => {
  const { email, password } = req.body;
  const identifier = String(email || '').trim();
  const normalizedEmail = normalizeEmail(identifier);
  const [phoneVariant1, phoneVariant2, phoneVariant3] = getPhoneLookupVariants(identifier);
  const rawPassword = String(password || '');
  const trimmedPassword = rawPassword.trim();
  const limiterKey = getLoginRateLimitKey(req, identifier);
  
  // Validate input
  if (!identifier || !rawPassword) {
    const reason = !identifier ? 'Missing email' : 'Missing password';
    db.run(`INSERT INTO login_history (email, ip_address, success, reason) VALUES (?, ?, ?, ?)`,
      [identifier || 'unknown', getClientIp(req), 0, reason]);
    return res.json({ success: false, message: 'Email and password required' });
  }

  db.all(
    `SELECT *
     FROM users
     WHERE LOWER(email) = ? OR phone IN (?, ?, ?)
     ORDER BY
       CASE WHEN LOWER(email) = ? THEN 0 ELSE 1 END,
       CASE WHEN status = 'approved' THEN 0 ELSE 1 END,
       datetime(created_at) DESC,
       id DESC`,
    [normalizedEmail, phoneVariant1, phoneVariant2, phoneVariant3, normalizedEmail],
    (err, rows) => {
      if (err) {
        console.error('Login error:', err);
        writeSecurityLog('login_error', req, { identifier });
        db.run(`INSERT INTO login_history (email, ip_address, success, reason) VALUES (?, ?, ?, ?)`,
          [identifier, getClientIp(req), 0, 'Database error']);
        return res.json({ success: false, message: 'Server error' });
      }

      const candidates = Array.isArray(rows) ? rows : [];

      if (!candidates.length) {
        writeSecurityLog('login_failed_no_user', req, { identifier });
        db.run(`INSERT INTO login_history (email, ip_address, success, reason) VALUES (?, ?, ?, ?)`,
          [identifier, getClientIp(req), 0, 'User not found']);
        return res.json({ success: false, message: 'Invalid credentials or not approved' });
      }

      let matchedRow = null;
      let passwordUsed = '';

      for (const row of candidates) {
        const rawPasswordValid = verifyPassword(rawPassword, row.password);
        const trimmedPasswordValid = !rawPasswordValid
          && trimmedPassword
          && trimmedPassword !== rawPassword
          && verifyPassword(trimmedPassword, row.password);

        if (rawPasswordValid || trimmedPasswordValid) {
          matchedRow = row;
          passwordUsed = rawPasswordValid ? rawPassword : trimmedPassword;
          break;
        }
      }

      if (!matchedRow) {
        const primaryRow = candidates[0];
        writeSecurityLog('login_failed_invalid_password', req, { userId: primaryRow.id, email: primaryRow.email });
        db.run(`INSERT INTO login_history (user_id, email, ip_address, success, reason) VALUES (?, ?, ?, ?, ?)`,
          [primaryRow.id, primaryRow.email, getClientIp(req), 0, 'Invalid password']);
        console.error('Password verification failed for user:', identifier);
        return res.json({ success: false, message: 'Invalid credentials or not approved' });
      }

      // Status check removed — all users with correct credentials can log in
      // Activity is still tracked and visible in admin panel

      // Password upgrade if needed
      if (!isBcryptHash(matchedRow.password)) {
        const upgradedHash = hashPassword(passwordUsed);
        db.run(`UPDATE users SET password = ? WHERE id = ?`, [upgradedHash, matchedRow.id], (updateErr) => {
          if (updateErr) {
            console.error('Password migration error:', updateErr);
          }
        });
      }

      // Login successful
      req.session.user = {
        id: matchedRow.id,
        name: matchedRow.name,
        email: matchedRow.email,
        phone: matchedRow.phone,
        balance: Number(matchedRow.balance || 0)
      };

      if (typeof loginRateLimiter.resetKey === 'function') {
        loginRateLimiter.resetKey(limiterKey);
      }
      
      writeSecurityLog('login_success', req, { userId: matchedRow.id, email: matchedRow.email });
      db.run(`INSERT INTO login_history (user_id, email, ip_address, success, reason) VALUES (?, ?, ?, ?, ?)`,
        [matchedRow.id, matchedRow.email, getClientIp(req), 1, 'Successful login']);
      
      return res.json({ success: true, message: 'Login successful', user: req.session.user });
    }
  );
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

app.get('/api/chat/session', requireAuth, (req, res) => {
  ensureChatConversation(req.session.user.id, (conversationErr, conversation) => {
    if (conversationErr) {
      console.error('Chat session error:', conversationErr);
      return res.status(500).json({ success: false, message: 'Failed to load chat session.' });
    }

    loadConversationMessages(conversation.id, req.session.user.id, (messagesErr, messages) => {
      if (messagesErr) {
        console.error('Chat messages load error:', messagesErr);
        return res.status(500).json({ success: false, message: 'Failed to load chat messages.' });
      }

      const latestMessage = messages.length ? messages[messages.length - 1] : null;
      getSupportAvailability((availabilityErr, agentOnline) => {
        if (availabilityErr) {
          console.error('Support availability error:', availabilityErr);
        }

        db.get(
          `SELECT rating, comment, created_at
           FROM chat_feedback
           WHERE conversation_id = ? AND user_id = ?`,
          [conversation.id, req.session.user.id],
          (feedbackErr, feedbackRow) => {
            if (feedbackErr) {
              console.error('Chat feedback lookup error:', feedbackErr);
            }

            return res.json({
              success: true,
              conversation: {
                id: conversation.id,
                status: conversation.status,
                assignedAgent: conversation.assigned_agent,
                userIdentifier: conversation.user_identifier,
                agentOnline: Boolean(agentOnline),
                latestMessageId: latestMessage ? latestMessage.id : 0
              },
              feedback: feedbackRow
                ? {
                  rating: Number(feedbackRow.rating || 0),
                  comment: feedbackRow.comment || '',
                  createdAt: feedbackRow.created_at
                }
                : null,
              messages
            });
          }
        );
      });
    });
  });
});

app.post('/api/chat/message', requireAuth, (req, res) => {
  const message = String(req.body?.message || '').trim();
  if (!message) {
    return res.status(400).json({ success: false, message: 'Message is required.' });
  }
  if (message.length > 1000) {
    return res.status(400).json({ success: false, message: 'Message is too long.' });
  }

  ensureChatConversation(req.session.user.id, (conversationErr, conversation) => {
    if (conversationErr) {
      console.error('Conversation lookup error:', conversationErr);
      return res.status(500).json({ success: false, message: 'Unable to open support chat.' });
    }

    const issueCategory = classifyChatIssue(message);
    insertChatMessage(conversation.id, 'user', message, req.session.user.name || null, (insertUserErr, userMessageId) => {
      if (insertUserErr) {
        console.error('User chat insert error:', insertUserErr);
        return res.status(500).json({ success: false, message: 'Failed to send message.' });
      }

      db.run(
        `INSERT INTO chat_issue_events (conversation_id, user_id, issue_category, source)
         VALUES (?, ?, ?, 'user')`,
        [conversation.id, req.session.user.id, issueCategory],
        () => {}
      );

      db.run(
        `UPDATE chat_conversations
         SET user_identifier = ?,
             last_user_message_at = CURRENT_TIMESTAMP,
             last_message_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [String(req.session.user.email || req.session.user.phone || ''), conversation.id]
      );

      const needsEscalation = shouldEscalateToHuman(message) || generateBotReply(message) === CHAT_FALLBACK_REPLY;
      getSupportAvailability((availabilityErr, agentOnline) => {
        if (availabilityErr) {
          console.error('Support availability read error:', availabilityErr);
        }

        const resolvedAgentOnline = Boolean(agentOnline);
        const conversationMode = String(conversation.status || 'bot').toLowerCase();

        if (conversationMode === 'human') {
          if (!resolvedAgentOnline) {
            const offlineMessage = 'Support is currently offline. Your message has been saved and a human agent will reply when available.';
            insertChatMessage(conversation.id, 'system', offlineMessage, 'System', (offlineErr) => {
              if (offlineErr) {
                console.error('Offline chat insert error:', offlineErr);
              }
              clearCachedChatMessages(req.session.user.id);
              return res.json({
                success: true,
                handoffRequested: true,
                agentOnline: false,
                latestMessageId: userMessageId,
                message: 'Message saved. Human support is currently offline.'
              });
            });
            return;
          }

          clearCachedChatMessages(req.session.user.id);
          return res.json({
            success: true,
            handoffRequested: true,
            agentOnline: true,
            latestMessageId: userMessageId,
            message: 'Message sent. A human support agent will reply shortly.'
          });
        }

        if (needsEscalation) {
          db.run(
            `UPDATE chat_conversations
             SET status = 'human', updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [conversation.id]
          );

          const handoffMessage = resolvedAgentOnline
            ? 'I am handing this over to a human support agent now. Please hold on.'
            : 'I have routed this to human support. Agents are currently offline, but your chat is saved and will be handled once they are online.';

          insertChatMessage(conversation.id, 'bot', handoffMessage, 'Agro Assistant', (handoffErr, handoffMessageId) => {
            if (handoffErr) {
              console.error('Handoff message insert error:', handoffErr);
            }

            db.run(
              `UPDATE chat_conversations
               SET last_agent_message_at = CURRENT_TIMESTAMP,
                   last_message_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP
               WHERE id = ?`,
              [conversation.id]
            );

            clearCachedChatMessages(req.session.user.id);
            return res.json({
              success: true,
              handoffRequested: true,
              agentOnline: resolvedAgentOnline,
              latestMessageId: handoffMessageId || userMessageId,
              message: handoffMessage
            });
          });
          return;
        }

        const botReply = generateBotReply(message);
        insertChatMessage(conversation.id, 'bot', botReply, 'Agro Assistant', (botErr, botMessageId) => {
          if (botErr) {
            console.error('Bot chat insert error:', botErr);
            return res.status(500).json({ success: false, message: 'Failed to generate bot response.' });
          }

          db.run(
            `UPDATE chat_conversations
             SET status = 'bot',
                 last_agent_message_at = CURRENT_TIMESTAMP,
                 last_message_at = CURRENT_TIMESTAMP,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [conversation.id]
          );

          clearCachedChatMessages(req.session.user.id);
          return res.json({
            success: true,
            handoffRequested: false,
            agentOnline: resolvedAgentOnline,
            latestMessageId: botMessageId,
            message: botReply
          });
        });
      });
    });
  });
});

app.get('/api/chat/messages', requireAuth, (req, res) => {
  const sinceId = Math.max(0, Number(req.query.sinceId || 0));
  ensureChatConversation(req.session.user.id, (conversationErr, conversation) => {
    if (conversationErr) {
      console.error('Chat poll conversation error:', conversationErr);
      return res.status(500).json({ success: false, message: 'Could not load chat updates.' });
    }

    db.all(
      `SELECT id, sender_type, sender_name, encrypted_message, created_at
       FROM chat_messages
       WHERE conversation_id = ? AND id > ?
       ORDER BY id ASC`,
      [conversation.id, sinceId],
      (err, rows) => {
        if (err) {
          console.error('Chat poll error:', err);
          return res.status(500).json({ success: false, message: 'Could not load chat updates.' });
        }

        const messages = (rows || []).map((row) => ({
          id: row.id,
          senderType: row.sender_type,
          senderName: row.sender_name,
          message: decryptChatMessage(row.encrypted_message),
          createdAt: row.created_at
        }));

        if (messages.length) {
          clearCachedChatMessages(req.session.user.id);
        }

        getSupportAvailability((availabilityErr, agentOnline) => {
          if (availabilityErr) {
            console.error('Support availability poll error:', availabilityErr);
          }

          res.json({
            success: true,
            conversation: {
              id: conversation.id,
              status: conversation.status,
              assignedAgent: conversation.assigned_agent,
              agentOnline: Boolean(agentOnline)
            },
            messages
          });
        });
      }
    );
  });
});

app.post('/api/chat/rating', requireAuth, (req, res) => {
  const rating = Number(req.body?.rating);
  const comment = String(req.body?.comment || '').trim();

  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ success: false, message: 'Rating must be from 1 to 5.' });
  }

  ensureChatConversation(req.session.user.id, (conversationErr, conversation) => {
    if (conversationErr) {
      console.error('Chat rating conversation error:', conversationErr);
      return res.status(500).json({ success: false, message: 'Could not save rating.' });
    }

    db.run(
      `INSERT INTO chat_feedback (conversation_id, user_id, rating, comment)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(conversation_id, user_id) DO UPDATE SET
         rating = excluded.rating,
         comment = excluded.comment,
         created_at = CURRENT_TIMESTAMP`,
      [conversation.id, req.session.user.id, rating, comment || null],
      function(err) {
        if (err) {
          console.error('Chat rating save error:', err);
          return res.status(500).json({ success: false, message: 'Failed to save rating.' });
        }

        return res.json({ success: true, message: 'Thanks for your feedback.' });
      }
    );
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
    `SELECT d.id, d.plan_id, d.plan_name, d.amount, d.status, d.payment_provider, d.payment_reference, d.mobile_number, d.approved_at, d.withdrawn_at, d.created_at,
            wr.id AS withdrawal_request_id,
            wr.status AS withdrawal_request_status,
            wr.destination_type AS withdrawal_destination_type,
            wr.provider_name AS withdrawal_provider_name,
            wr.account_name AS withdrawal_account_name,
            wr.account_number AS withdrawal_account_number,
            wr.note AS withdrawal_note,
            wr.admin_note AS withdrawal_admin_note,
            wr.requested_at AS withdrawal_requested_at,
            wr.processed_at AS withdrawal_processed_at
     FROM deposits d
     LEFT JOIN withdrawal_requests wr
       ON wr.id = (
         SELECT id
         FROM withdrawal_requests
         WHERE deposit_id = d.id
         ORDER BY requested_at DESC, id DESC
         LIMIT 1
       )
     WHERE user_id = ?
     ORDER BY d.created_at DESC, d.id DESC`,
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

        return {
          ...deposit,
          payout_multiplier: plan.payoutMultiplier,
          payout_days: plan.payoutDays,
          projected_payout: progress.projectedPayout,
          daily_income: progress.dailyIncome,
          current_value: progress.currentValue,
          elapsed_days: progress.elapsedDays,
          remaining_days: progress.remainingDays,
          progress_percent: progress.progressPercent,
          is_matured: progress.isMatured,
          payout_due_at: progress.payoutDueAt
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
    `INSERT INTO deposits (user_id, plan_id, plan_name, amount, status, payment_provider, payment_reference, mobile_number, approved_at) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, CURRENT_TIMESTAMP)`,
    [req.session.user.id, plan.id, plan.name, roundedAmount, provider, reference, phone],
    function(insertErr) {
      if (insertErr) {
        console.error('Error creating deposit:', insertErr);
        return res.status(500).json({ success: false, message: 'Failed to create deposit' });
      }

      const depositId = this.lastID;

      res.json({
        success: true,
        message: 'Deposit successful and your investment is now active.',
        deposit: {
          id: depositId,
          planId: plan.id,
          planName: plan.name,
          amount: roundedAmount,
          status: 'approved',
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

app.post('/api/deposits/:id/withdraw', requireAuth, (req, res) => {
  const depositId = Number(req.params.id);
  const destinationType = String(req.body?.destinationType || '').trim().toLowerCase();
  const providerName = String(req.body?.providerName || '').trim();
  const accountName = String(req.body?.accountName || '').trim();
  const accountNumber = String(req.body?.accountNumber || '').trim();
  const note = String(req.body?.note || '').trim();

  if (!depositId) {
    return res.status(400).json({ success: false, message: 'Invalid deposit id' });
  }

  if (!['momo', 'bank'].includes(destinationType)) {
    return res.status(400).json({ success: false, message: 'Select a valid payout destination.' });
  }

  if (!providerName || !accountName || !accountNumber) {
    return res.status(400).json({ success: false, message: 'Provider, account name, and account number are required.' });
  }

  db.get(
    `SELECT id, user_id, plan_id, plan_name, amount, status, approved_at, withdrawn_at
     FROM deposits
     WHERE id = ? AND user_id = ?`,
    [depositId, req.session.user.id],
    (findErr, deposit) => {
      if (findErr) {
        console.error('Withdraw lookup error:', findErr);
        return res.status(500).json({ success: false, message: 'Server error' });
      }

      if (!deposit) {
        return res.status(404).json({ success: false, message: 'Deposit not found' });
      }

      if (deposit.status === 'withdrawn') {
        return res.status(400).json({ success: false, message: 'This deposit has already been withdrawn.' });
      }

      if (deposit.status !== 'approved' || !deposit.approved_at) {
        return res.status(400).json({ success: false, message: 'This deposit is not active for withdrawal yet.' });
      }

      const plan = INVESTMENT_PLANS.find((item) => item.id === deposit.plan_id);
      if (!plan) {
        return res.status(400).json({ success: false, message: 'Invalid plan for this deposit.' });
      }

      const payoutDueAt = getPayoutDueAt(deposit.approved_at, plan.payoutDays);
      if (!payoutDueAt || Date.now() < payoutDueAt.getTime()) {
        const remainingMs = payoutDueAt ? Math.max(0, payoutDueAt.getTime() - Date.now()) : (plan.payoutDays * 24 * 60 * 60 * 1000);
        const remainingDays = Math.max(1, Math.ceil(remainingMs / (24 * 60 * 60 * 1000)));
        return res.status(400).json({
          success: false,
          message: `Withdrawal is available after exactly ${plan.payoutDays} days. ${remainingDays} day(s) remaining.`
        });
      }

      const payout = Math.round((Number(deposit.amount || 0) * Number(plan.payoutMultiplier || 1)) * 100) / 100;

      db.get(
        `SELECT id, status
         FROM withdrawal_requests
         WHERE deposit_id = ?
         ORDER BY requested_at DESC, id DESC
         LIMIT 1`,
        [depositId],
        (requestErr, existingRequest) => {
          if (requestErr) {
            console.error('Withdrawal request lookup error:', requestErr);
            return res.status(500).json({ success: false, message: 'Failed to check previous withdrawal requests.' });
          }

          if (existingRequest && existingRequest.status === 'pending') {
            return res.status(400).json({ success: false, message: 'You already have a pending withdrawal request for this deposit.' });
          }

          db.run(
            `INSERT INTO withdrawal_requests (
              deposit_id, user_id, payout_amount, destination_type, provider_name,
              account_name, account_number, note, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
            [depositId, req.session.user.id, payout, destinationType, providerName, accountName, accountNumber, note || null],
            function(insertErr) {
              if (insertErr) {
                console.error('Withdrawal request insert error:', insertErr);
                return res.status(500).json({ success: false, message: 'Failed to submit withdrawal request.' });
              }

              return res.json({
                success: true,
                message: `${deposit.plan_name} withdrawal request submitted for admin review.`,
                payout,
                payoutDays: plan.payoutDays,
                requestId: this.lastID
              });
            }
          );
        }
      );
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

app.get('/api/admin/security-logs', (req, res) => {
  const limit = Number(req.query.limit || 100);
  const logs = readRecentSecurityLogs(limit);
  res.json({
    success: true,
    logPath: SECURITY_LOG_PATH,
    count: logs.length,
    logs
  });
});

app.get('/api/admin/login-history', (req, res) => {
  const limit = Math.min(Number(req.query.limit || 100), 1000);
  const email = req.query.email ? String(req.query.email).trim().toLowerCase() : null;

  let query = `SELECT id, user_id, email, login_time, ip_address, success, reason FROM login_history ORDER BY login_time DESC LIMIT ?`;
  let params = [limit];

  if (email) {
    query = `SELECT id, user_id, email, login_time, ip_address, success, reason FROM login_history WHERE LOWER(email) = ? ORDER BY login_time DESC LIMIT ?`;
    params = [email, limit];
  }

  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Login history query error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    res.json({
      success: true,
      count: (rows || []).length,
      data: rows || []
    });
  });
});

app.get('/api/admin/withdrawal-requests', (req, res) => {
  db.all(
    `SELECT wr.id, wr.deposit_id, wr.user_id, wr.payout_amount, wr.destination_type, wr.provider_name,
            wr.account_name, wr.account_number, wr.note, wr.status, wr.admin_note, wr.requested_at,
            wr.processed_at, wr.processed_by,
            d.plan_name, d.amount AS deposit_amount,
            u.name AS user_name, u.email AS user_email
     FROM withdrawal_requests wr
     INNER JOIN deposits d ON d.id = wr.deposit_id
     INNER JOIN users u ON u.id = wr.user_id
     ORDER BY CASE WHEN wr.status = 'pending' THEN 0 ELSE 1 END, wr.requested_at DESC, wr.id DESC`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Error loading withdrawal requests:', err);
        return res.status(500).json({ success: false, message: 'Failed to load withdrawal requests.' });
      }

      res.json({ success: true, requests: rows || [] });
    }
  );
});

app.get('/api/admin/chat/conversations', (req, res) => {
  db.all(
    `SELECT c.id, c.user_id, c.user_identifier, c.status, c.assigned_agent,
            c.last_user_message_at, c.last_agent_message_at, c.last_message_at,
            c.created_at, c.updated_at,
            u.name AS user_name, u.email AS user_email, u.phone AS user_phone,
            (SELECT COUNT(*) FROM chat_messages cm WHERE cm.conversation_id = c.id) AS total_messages,
            (SELECT encrypted_message FROM chat_messages cm2 WHERE cm2.conversation_id = c.id ORDER BY cm2.id DESC LIMIT 1) AS latest_encrypted_message,
            (SELECT sender_type FROM chat_messages cm3 WHERE cm3.conversation_id = c.id ORDER BY cm3.id DESC LIMIT 1) AS latest_sender_type,
            (SELECT created_at FROM chat_messages cm4 WHERE cm4.conversation_id = c.id ORDER BY cm4.id DESC LIMIT 1) AS latest_message_at
     FROM chat_conversations c
     INNER JOIN users u ON u.id = c.user_id
     ORDER BY datetime(COALESCE(c.last_message_at, c.updated_at)) DESC, c.id DESC`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Admin chat conversations error:', err);
        return res.status(500).json({ success: false, message: 'Failed to load chat conversations.' });
      }

      getSupportAvailability((availabilityErr, agentOnline) => {
        if (availabilityErr) {
          console.error('Support availability admin error:', availabilityErr);
        }

        const conversations = (rows || []).map((row) => ({
          id: row.id,
          userId: row.user_id,
          userName: row.user_name,
          userEmail: row.user_email,
          userPhone: row.user_phone,
          userIdentifier: row.user_identifier,
          status: row.status,
          assignedAgent: row.assigned_agent,
          totalMessages: Number(row.total_messages || 0),
          lastMessageAt: row.latest_message_at || row.last_message_at || row.updated_at,
          lastSenderType: row.latest_sender_type || null,
          lastMessagePreview: decryptChatMessage(row.latest_encrypted_message || '').slice(0, 220)
        }));

        res.json({
          success: true,
          agentOnline: Boolean(agentOnline),
          conversations
        });
      });
    }
  );
});

app.get('/api/admin/chat/messages/:conversationId', (req, res) => {
  const conversationId = Number(req.params.conversationId);
  if (!conversationId) {
    return res.status(400).json({ success: false, message: 'Invalid conversation id.' });
  }

  db.all(
    `SELECT cm.id, cm.sender_type, cm.sender_name, cm.encrypted_message, cm.created_at,
            c.status, c.assigned_agent, c.user_identifier
     FROM chat_messages cm
     INNER JOIN chat_conversations c ON c.id = cm.conversation_id
     WHERE cm.conversation_id = ?
     ORDER BY cm.id ASC`,
    [conversationId],
    (err, rows) => {
      if (err) {
        console.error('Admin chat messages error:', err);
        return res.status(500).json({ success: false, message: 'Failed to load chat messages.' });
      }

      const messages = (rows || []).map((row) => ({
        id: row.id,
        senderType: row.sender_type,
        senderName: row.sender_name,
        message: decryptChatMessage(row.encrypted_message),
        createdAt: row.created_at
      }));

      const first = rows && rows[0] ? rows[0] : null;
      return res.json({
        success: true,
        conversation: first
          ? {
            id: conversationId,
            status: first.status,
            assignedAgent: first.assigned_agent,
            userIdentifier: first.user_identifier
          }
          : { id: conversationId },
        messages
      });
    }
  );
});

app.post('/api/admin/chat/availability', (req, res) => {
  const isOnline = Boolean(req.body?.online);
  db.run(
    `INSERT INTO support_settings (setting_key, setting_value, updated_at)
     VALUES ('agent_online', ?, CURRENT_TIMESTAMP)
     ON CONFLICT(setting_key) DO UPDATE SET
       setting_value = excluded.setting_value,
       updated_at = CURRENT_TIMESTAMP`,
    [isOnline ? '1' : '0'],
    (err) => {
      if (err) {
        console.error('Support availability update error:', err);
        return res.status(500).json({ success: false, message: 'Failed to update availability.' });
      }
      return res.json({ success: true, online: isOnline });
    }
  );
});

app.post('/api/admin/chat/takeover/:conversationId', (req, res) => {
  const conversationId = Number(req.params.conversationId);
  if (!conversationId) {
    return res.status(400).json({ success: false, message: 'Invalid conversation id.' });
  }

  db.run(
    `UPDATE chat_conversations
     SET status = 'human', assigned_agent = ?, updated_at = CURRENT_TIMESTAMP
     WHERE id = ?`,
    [CHAT_DEFAULT_AGENT_NAME, conversationId],
    function(err) {
      if (err) {
        console.error('Chat takeover update error:', err);
        return res.status(500).json({ success: false, message: 'Failed to take over chat.' });
      }

      if (!this.changes) {
        return res.status(404).json({ success: false, message: 'Conversation not found.' });
      }

      insertChatMessage(conversationId, 'system', 'A human support agent has joined this chat.', 'System', () => {});
      return res.json({ success: true, message: 'Human takeover enabled.' });
    }
  );
});

app.post('/api/admin/chat/reply/:conversationId', (req, res) => {
  const conversationId = Number(req.params.conversationId);
  const message = String(req.body?.message || '').trim();
  const markResolved = Boolean(req.body?.markResolved);

  if (!conversationId || !message) {
    return res.status(400).json({ success: false, message: 'Conversation id and reply message are required.' });
  }

  if (message.length > 1000) {
    return res.status(400).json({ success: false, message: 'Reply is too long.' });
  }

  insertChatMessage(conversationId, 'agent', message, CHAT_DEFAULT_AGENT_NAME, (insertErr, messageId) => {
    if (insertErr) {
      console.error('Admin chat reply insert error:', insertErr);
      return res.status(500).json({ success: false, message: 'Failed to send reply.' });
    }

    const nextStatus = markResolved ? 'resolved' : 'human';
    db.run(
      `UPDATE chat_conversations
       SET status = ?, assigned_agent = ?,
           last_agent_message_at = CURRENT_TIMESTAMP,
           last_message_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [nextStatus, CHAT_DEFAULT_AGENT_NAME, conversationId],
      () => {}
    );

    db.get(`SELECT user_id FROM chat_conversations WHERE id = ?`, [conversationId], (findErr, convoRow) => {
      if (!findErr && convoRow && convoRow.user_id) {
        clearCachedChatMessages(convoRow.user_id);
      }
      return res.json({ success: true, messageId, status: nextStatus });
    });
  });
});

app.get('/api/admin/chat/analytics', (req, res) => {
  db.all(
    `SELECT issue_category, COUNT(*) AS total
     FROM chat_issue_events
     WHERE created_at >= datetime('now', '-30 day')
     GROUP BY issue_category
     ORDER BY total DESC`,
    [],
    (issueErr, issueRows) => {
      if (issueErr) {
        console.error('Chat analytics issue query error:', issueErr);
        return res.status(500).json({ success: false, message: 'Failed to load chat analytics.' });
      }

      db.get(
        `SELECT
            COUNT(*) AS total_conversations,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved_conversations,
            SUM(CASE WHEN status = 'human' THEN 1 ELSE 0 END) AS human_conversations,
            SUM(CASE WHEN status = 'bot' THEN 1 ELSE 0 END) AS bot_conversations
         FROM chat_conversations`,
        [],
        (summaryErr, summaryRow) => {
          if (summaryErr) {
            console.error('Chat analytics summary query error:', summaryErr);
            return res.status(500).json({ success: false, message: 'Failed to load chat analytics.' });
          }

          db.get(
            `SELECT ROUND(AVG(rating), 2) AS average_rating, COUNT(*) AS total_feedback
             FROM chat_feedback`,
            [],
            (ratingErr, ratingRow) => {
              if (ratingErr) {
                console.error('Chat analytics rating query error:', ratingErr);
                return res.status(500).json({ success: false, message: 'Failed to load chat analytics.' });
              }

              return res.json({
                success: true,
                trends: issueRows || [],
                summary: {
                  totalConversations: Number((summaryRow && summaryRow.total_conversations) || 0),
                  resolvedConversations: Number((summaryRow && summaryRow.resolved_conversations) || 0),
                  humanConversations: Number((summaryRow && summaryRow.human_conversations) || 0),
                  botConversations: Number((summaryRow && summaryRow.bot_conversations) || 0)
                },
                feedback: {
                  averageRating: Number((ratingRow && ratingRow.average_rating) || 0),
                  totalFeedback: Number((ratingRow && ratingRow.total_feedback) || 0)
                }
              });
            }
          );
        }
      );
    }
  );
});

app.post('/api/admin/approve-withdrawal/:id', (req, res) => {
  const requestId = Number(req.params.id);
  const adminNote = String(req.body?.adminNote || '').trim();
  if (!requestId) {
    return res.status(400).json({ success: false, message: 'Invalid withdrawal request id.' });
  }

  db.get(
    `SELECT wr.id, wr.deposit_id, wr.user_id, wr.payout_amount, wr.provider_name,
            wr.account_name, wr.account_number, wr.status,
            d.status AS deposit_status, d.plan_name,
            u.email AS user_email, u.name AS user_name
     FROM withdrawal_requests wr
     INNER JOIN deposits d ON d.id = wr.deposit_id
     INNER JOIN users u ON u.id = wr.user_id
     WHERE wr.id = ?`,
    [requestId],
    (findErr, requestRow) => {
      if (findErr) {
        console.error('Withdrawal approval lookup error:', findErr);
        return res.status(500).json({ success: false, message: 'Failed to load withdrawal request.' });
      }

      if (!requestRow || requestRow.status !== 'pending') {
        return res.status(404).json({ success: false, message: 'Pending withdrawal request not found.' });
      }

      if (String(requestRow.deposit_status || '').toLowerCase() !== 'approved') {
        return res.status(400).json({ success: false, message: 'Only approved deposits can be withdrawn.' });
      }

      db.run(
        `UPDATE withdrawal_requests
         SET status = 'approved', admin_note = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ?
         WHERE id = ? AND status = 'pending'`,
        [adminNote || null, ADMIN_USERNAME, requestId],
        function(updateRequestErr) {
          if (updateRequestErr) {
            console.error('Withdrawal approval update error:', updateRequestErr);
            return res.status(500).json({ success: false, message: 'Failed to approve withdrawal request.' });
          }

          if (!this.changes) {
            return res.status(400).json({ success: false, message: 'Withdrawal request could not be updated.' });
          }

          db.run(
            `UPDATE deposits
             SET status = 'withdrawn', withdrawn_at = CURRENT_TIMESTAMP
             WHERE id = ? AND status = 'approved'`,
            [requestRow.deposit_id],
            function(updateDepositErr) {
              if (updateDepositErr) {
                console.error('Deposit withdrawal update error:', updateDepositErr);
                return res.status(500).json({ success: false, message: 'Withdrawal approved, but deposit status failed to update.' });
              }

              res.json({ success: true, message: 'Withdrawal marked as paid manually.' });
            }
          );
        }
      );
    }
  );
});

app.post('/api/admin/reject-withdrawal/:id', (req, res) => {
  const requestId = Number(req.params.id);
  const adminNote = String(req.body?.adminNote || '').trim();
  if (!requestId) {
    return res.status(400).json({ success: false, message: 'Invalid withdrawal request id.' });
  }

  db.get(
    `SELECT wr.id, wr.payout_amount, wr.provider_name, wr.account_name, wr.account_number,
            wr.status, d.plan_name, u.email AS user_email, u.name AS user_name
     FROM withdrawal_requests wr
     INNER JOIN deposits d ON d.id = wr.deposit_id
     INNER JOIN users u ON u.id = wr.user_id
     WHERE wr.id = ?`,
    [requestId],
    (findErr, requestRow) => {
      if (findErr) {
        console.error('Withdrawal rejection lookup error:', findErr);
        return res.status(500).json({ success: false, message: 'Failed to load withdrawal request.' });
      }

      if (!requestRow || requestRow.status !== 'pending') {
        return res.status(404).json({ success: false, message: 'Pending withdrawal request not found.' });
      }

      db.run(
        `UPDATE withdrawal_requests
         SET status = 'rejected', admin_note = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ?
         WHERE id = ? AND status = 'pending'`,
        [adminNote || null, ADMIN_USERNAME, requestId],
        function(updateErr) {
          if (updateErr) {
            console.error('Withdrawal rejection update error:', updateErr);
            return res.status(500).json({ success: false, message: 'Failed to reject withdrawal request.' });
          }

          if (!this.changes) {
            return res.status(400).json({ success: false, message: 'Withdrawal request could not be updated.' });
          }

          res.json({ success: true, message: 'Withdrawal request rejected.' });
        }
      );
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
    }
  );
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.json({ success: false, message: 'Failed to logout' });
    }
    res.clearCookie('agropluse.sid');
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

app.get('/health', (req, res) => {
  db.get('SELECT 1 AS ok', [], (err) => {
    if (err) {
      return res.status(503).json({
        success: false,
        status: 'unhealthy',
        message: 'Database check failed'
      });
    }

    return res.json({
      success: true,
      status: 'healthy',
      uptime: Math.round(process.uptime()),
      timestamp: new Date().toISOString()
    });
  });
});

app.use('/api', (req, res) => {
  return res.status(404).json({ success: false, message: 'API endpoint not found' });
});

const server = app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

server.on('error', (error) => {
  if (error && error.code === 'EADDRINUSE') {
    console.log(`Port ${PORT} is already in use. Existing Agro Pluse server is likely already running.`);
    process.exit(0);
    return;
  }

  console.error('Server startup error:', error);
  process.exit(1);
});