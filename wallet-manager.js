const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Validate encryption key
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
  throw new Error('ENCRYPTION_KEY must be exactly 32 characters for AES-256');
}

// Create data directory if it doesn't exist
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const WALLETS_FILE = path.join(DATA_DIR, 'wallets.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

// Initialize wallets storage
function initializeWalletStorage() {
  if (!fs.existsSync(WALLETS_FILE)) {
    fs.writeFileSync(WALLETS_FILE, JSON.stringify({}), 'utf8');
  }
  if (!fs.existsSync(SESSIONS_FILE)) {
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify({}), 'utf8');
    fs.chmodSync(SESSIONS_FILE, 0o600);
  }
}

// Encrypt private key
function encryptPrivateKey(privateKey, encryptionKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(encryptionKey), iv);

  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted,
    authTag
  };
}

// Decrypt private key
function decryptPrivateKey(encryptedData, iv, authTag, encryptionKey) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(encryptionKey),
    Buffer.from(iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// Derive encryption key from password and salt
function deriveKey(password, salt) {
  // PBKDF2 with 100,000 iterations, 32 bytes (256 bits), sha256
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// Load all wallets
function loadWallets() {
  initializeWalletStorage();
  const wallets = JSON.parse(fs.readFileSync(WALLETS_FILE, 'utf8'));
  
  // Migration: Ensure all users have contacts, guardrails and key salts
  let changed = false;
  for (const userId in wallets) {
    if (!wallets[userId].contacts) {
      wallets[userId].contacts = {};
      changed = true;
    }
    if (!wallets[userId].guardrails) {
      wallets[userId].guardrails = {
        dailyLimit: "1.0",
        spentToday: "0",
        lastSpentDate: new Date().toISOString().split('T')[0],
        whitelist: []
      };
      changed = true;
    }
    if (!wallets[userId].transactions) {
      wallets[userId].transactions = [];
      changed = true;
    }
    if (!wallets[userId].securityLogs) {
      wallets[userId].securityLogs = [];
      changed = true;
    }
    if (typeof wallets[userId].paymentSecretHash === 'undefined') {
      wallets[userId].paymentSecretHash = null;
      changed = true;
    }
    if (typeof wallets[userId].authVersion === 'undefined') {
      wallets[userId].authVersion = 1;
      changed = true;
    }
    if (!wallets[userId].keySalt) {
      // For legacy wallets, we'll keep using the global ENCRYPTION_KEY
      // We don't add a salt here to avoid breaking them
    }
  }
  
  if (changed) saveWallets(wallets);
  return wallets;
}

// Save wallets
function saveWallets(wallets) {
  fs.writeFileSync(WALLETS_FILE, JSON.stringify(wallets, null, 2), 'utf8');
}

// Create a new wallet for a user
async function createWallet(userId, password) {
  const wallets = loadWallets();

  if (wallets[userId]) {
    return {
      success: false,
      message: 'User already exists',
      address: wallets[userId].address
    };
  }

  if (!password) {
    return { success: false, message: 'Password is required' };
  }

  // Generate a new wallet
  const wallet = ethers.Wallet.createRandom();
  const privateKey = wallet.privateKey;
  const address = wallet.address;

  // Generate a unique salt for this user's key derivation
  const keySalt = crypto.randomBytes(16).toString('hex');
  const userEncryptionKey = deriveKey(password, keySalt);

  // Encrypt the private key with the user-derived key
  const encryptedKey = encryptPrivateKey(privateKey, userEncryptionKey);

  // Hash the password for login verification
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store wallet info
  wallets[userId] = {
    address,
    hashedPassword,
    keySalt, // Store the salt for key derivation
    paymentSecretHash: null,
    authVersion: 1,
    encryptedKey: encryptedKey.encryptedData,
    iv: encryptedKey.iv,
    authTag: encryptedKey.authTag,
    createdAt: new Date().toISOString(),
    contacts: {}, // Mapping of handles to addresses
    guardrails: {
      dailyLimit: "1.0", // Default 1 ETH daily limit
      spentToday: "0",
      lastSpentDate: new Date().toISOString().split('T')[0],
      whitelist: [] // Array of whitelisted addresses
    },
    transactions: [],
    securityLogs: [
      { event: 'Wallet Created', timestamp: new Date().toISOString(), severity: 'low' }
    ]
  };

  saveWallets(wallets);

  return { success: true, address };
}

// Verify user password
async function verifyPassword(userId, password) {
  const wallets = loadWallets();
  const user = wallets[userId];

  if (!user || !user.hashedPassword) {
    return false;
  }

  const isValid = await bcrypt.compare(password, user.hashedPassword);
  
  if (!isValid) {
    logSecurityEvent(userId, 'Failed Login Attempt', 'high');
  }

  return isValid;
}

// Rotate user password/PIN and re-encrypt the private key with a new derived key.
async function resetPassword(userId, currentPassword, newPassword) {
  const wallets = loadWallets();
  const user = wallets[userId];

  if (!user) return { success: false, message: 'User not found' };
  if (!currentPassword) return { success: false, message: 'Current password is required' };
  if (!newPassword || typeof newPassword !== 'string') {
    return { success: false, message: 'New password is required' };
  }

  const trimmedNew = newPassword.trim();
  if (trimmedNew.length < 6) {
    return { success: false, message: 'New password/PIN must be at least 6 characters' };
  }
  if (trimmedNew === currentPassword) {
    return { success: false, message: 'New password must be different from current password' };
  }

  const isValid = await verifyPassword(userId, currentPassword);
  if (!isValid) return { success: false, message: 'Current password is invalid' };

  try {
    const oldKey = user.keySalt
      ? deriveKey(currentPassword, user.keySalt)
      : Buffer.from(ENCRYPTION_KEY);

    const privateKey = decryptPrivateKey(
      user.encryptedKey,
      user.iv,
      user.authTag,
      oldKey
    );

    const newSalt = crypto.randomBytes(16).toString('hex');
    const newKey = deriveKey(trimmedNew, newSalt);
    const reEncrypted = encryptPrivateKey(privateKey, newKey);
    const hashedPassword = await bcrypt.hash(trimmedNew, 10);

    wallets[userId].hashedPassword = hashedPassword;
    wallets[userId].authVersion = (wallets[userId].authVersion || 1) + 1;
    wallets[userId].keySalt = newSalt;
    wallets[userId].encryptedKey = reEncrypted.encryptedData;
    wallets[userId].iv = reEncrypted.iv;
    wallets[userId].authTag = reEncrypted.authTag;

    if (!wallets[userId].securityLogs) wallets[userId].securityLogs = [];
    wallets[userId].securityLogs.push({
      event: 'Password/PIN Reset',
      timestamp: new Date().toISOString(),
      severity: 'medium'
    });

    saveWallets(wallets);
    return { success: true, message: 'Password/PIN updated successfully.' };
  } catch (err) {
    console.error(`Password reset failed for user ${userId}:`, err.message);
    logSecurityEvent(userId, 'Password/PIN Reset Failed', 'high');
    return { success: false, message: 'Password reset failed. Please try again.' };
  }
}

async function setPaymentSecret(userId, secret) {
  const wallets = loadWallets();
  const user = wallets[userId];
  if (!user) return { success: false, message: 'User not found' };
  if (!secret || typeof secret !== 'string') {
    return { success: false, message: 'Payment secret is required' };
  }

  const trimmed = secret.trim();
  if (trimmed.length < 4) {
    return { success: false, message: 'Payment secret must be at least 4 characters' };
  }

  wallets[userId].paymentSecretHash = await bcrypt.hash(trimmed, 10);
  if (!wallets[userId].securityLogs) wallets[userId].securityLogs = [];
  wallets[userId].securityLogs.push({
    event: 'Payment Secret Set/Updated',
    timestamp: new Date().toISOString(),
    severity: 'medium'
  });
  saveWallets(wallets);

  return { success: true, message: 'Payment secret updated. Use `confirm <secret>` to approve payments.' };
}

async function verifyPaymentSecret(userId, secret) {
  const user = getWallet(userId);
  if (!user || !user.paymentSecretHash) return false;
  if (!secret || typeof secret !== 'string') return false;
  return bcrypt.compare(secret.trim(), user.paymentSecretHash);
}

function getAuthVersion(userId) {
  const wallet = getWallet(userId);
  return wallet?.authVersion || 1;
}

function hasPaymentSecret(userId) {
  const user = getWallet(userId);
  return !!(user && user.paymentSecretHash);
}

// Get wallet for a user
function getWallet(userId) {
  const wallets = loadWallets();
  return wallets[userId];
}

// Get a sanitized version of the wallet (no sensitive data)
function getSafeWallet(userId) {
  const wallet = getWallet(userId);
  if (!wallet) return null;
  
  const { hashedPassword, paymentSecretHash, encryptedKey, iv, authTag, keySalt, ...safeWallet } = wallet;
  return safeWallet;
}

// Get wallet instance for a user (with decrypted private key)
function getWalletInstance(userId, provider, password) {
  const walletInfo = getWallet(userId);

  if (!walletInfo) {
    return null;
  }

  let encryptionKey;
  if (walletInfo.keySalt && password) {
    // New hardened wallet: derive key from password
    encryptionKey = deriveKey(password, walletInfo.keySalt);
  } else {
    // Legacy wallet or password missing: use global ENCRYPTION_KEY
    encryptionKey = Buffer.from(ENCRYPTION_KEY);
  }

  try {
    const privateKey = decryptPrivateKey(
      walletInfo.encryptedKey,
      walletInfo.iv,
      walletInfo.authTag,
      encryptionKey
    );

    return new ethers.Wallet(privateKey, provider);
  } catch (err) {
    console.error(`Decryption failed for user ${userId}:`, err.message);
    logSecurityEvent(userId, 'Private Key Decryption Failed', 'high');
    return null;
  }
}

// List all wallet addresses
function listWallets() {
  const wallets = loadWallets();
  const addresses = {};

  for (const [userId, wallet] of Object.entries(wallets)) {
    addresses[userId] = wallet.address;
  }

  return addresses;
}

// Add a contact for a user
function addContact(userId, handle, address) {
  const wallets = loadWallets();
  if (!wallets[userId]) return { success: false, message: 'User not found' };
  
  if (!wallets[userId].contacts) wallets[userId].contacts = {};
  wallets[userId].contacts[handle.toLowerCase()] = address;
  
  saveWallets(wallets);
  return { success: true, message: `Contact ${handle} added.` };
}

// Get contact address
function getContactAddress(userId, handle) {
  const wallets = loadWallets();
  if (!wallets[userId] || !wallets[userId].contacts) return null;
  return wallets[userId].contacts[handle.toLowerCase()];
}

// Update guardrails
function updateGuardrails(userId, dailyLimit, whitelist) {
  const wallets = loadWallets();
  if (!wallets[userId]) return { success: false, message: 'User not found' };
  
  if (!wallets[userId].guardrails) {
    wallets[userId].guardrails = { dailyLimit: "1.0", spentToday: "0", lastSpentDate: new Date().toISOString().split('T')[0], whitelist: [] };
  }
  
  if (dailyLimit) wallets[userId].guardrails.dailyLimit = dailyLimit.toString();
  if (whitelist) wallets[userId].guardrails.whitelist = whitelist;
  
  saveWallets(wallets);
  return { success: true, message: 'Guardrails updated.' };
}

// Check and update daily limit
function checkAndUpdateLimit(userId, amount) {
  const wallets = loadWallets();
  const user = wallets[userId];
  if (!user || !user.guardrails) return true; // No guardrails, allow

  const today = new Date().toISOString().split('T')[0];
  if (user.guardrails.lastSpentDate !== today) {
    user.guardrails.spentToday = "0";
    user.guardrails.lastSpentDate = today;
  }

  const spent = parseFloat(user.guardrails.spentToday);
  const limit = parseFloat(user.guardrails.dailyLimit);
  const requested = parseFloat(amount);

  if (spent + requested > limit) {
    return false;
  }

  user.guardrails.spentToday = (spent + requested).toString();
  saveWallets(wallets);
  return true;
}

// Record a transaction
function recordTransaction(userId, txData) {
  const wallets = loadWallets();
  if (!wallets[userId]) return;
  
  if (!wallets[userId].transactions) wallets[userId].transactions = [];
  
  wallets[userId].transactions.unshift({
    ...txData,
    timestamp: new Date().toISOString()
  });
  
  // Keep only last 50 transactions
  if (wallets[userId].transactions.length > 50) {
    wallets[userId].transactions = wallets[userId].transactions.slice(0, 50);
  }
  
  saveWallets(wallets);
}

// Log a security event
function logSecurityEvent(userId, event, severity = 'low') {
  const wallets = loadWallets();
  if (!wallets[userId]) return;
  
  if (!wallets[userId].securityLogs) wallets[userId].securityLogs = [];
  wallets[userId].securityLogs.push({
    event,
    timestamp: new Date().toISOString(),
    severity
  });
  
  saveWallets(wallets);
}

// Get security status
function getSecurityStatus(userId) {
  const wallet = getWallet(userId);
  if (!wallet) return null;
  
  const logs = wallet.securityLogs || [];
  const score = calculateSecurityScore(logs);

  return {
    score,
    recentLogs: logs.slice(-5).reverse(),
    status: score > 80 ? 'Secure' : score > 50 ? 'Warning' : 'Critical'
  };
}

function calculateSecurityScore(logs = []) {
  const highSeverityLogs = logs.filter(l => l.severity === 'high');

  // Separate high-severity failed-login noise from critical security failures.
  const failedLoginHighLogs = highSeverityLogs.filter(l => l.event === 'Failed Login Attempt');
  const criticalHighLogs = highSeverityLogs.filter(l => l.event !== 'Failed Login Attempt');

  // Score model:
  // - Critical high events are severe.
  // - Failed login attempts apply only a tiny penalty to avoid permanently showing "unsafe".
  let score = 100;
  score -= (criticalHighLogs.length * 10);
  score -= (failedLoginHighLogs.length * 0.01);
  score = Number(Math.max(score, 0).toFixed(2));
  return score;
}

// Session Management
function loadSessions() {
  initializeWalletStorage();
  try {
    return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  } catch (err) {
    return {};
  }
}

function saveSessions(sessions) {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2), 'utf8');
}

// Export functions
module.exports = {
  createWallet,
  getWallet,
  getSafeWallet,
  getWalletInstance,
  listWallets,
  verifyPassword,
  resetPassword,
  setPaymentSecret,
  verifyPaymentSecret,
  hasPaymentSecret,
  getAuthVersion,
  addContact,
  getContactAddress,
  updateGuardrails,
  checkAndUpdateLimit,
  recordTransaction,
  logSecurityEvent,
  getSecurityStatus,
  calculateSecurityScore,
  loadSessions,
  saveSessions
};
