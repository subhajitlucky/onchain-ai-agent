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

// Initialize wallets storage
function initializeWalletStorage() {
  if (!fs.existsSync(WALLETS_FILE)) {
    fs.writeFileSync(WALLETS_FILE, JSON.stringify({}), 'utf8');
  }
}

// Encrypt private key
function encryptPrivateKey(privateKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);

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
function decryptPrivateKey(encryptedData, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(ENCRYPTION_KEY),
    Buffer.from(iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// Load all wallets
function loadWallets() {
  initializeWalletStorage();
  const wallets = JSON.parse(fs.readFileSync(WALLETS_FILE, 'utf8'));
  
  // Migration: Ensure all users have contacts and guardrails
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

  // Encrypt the private key
  const encryptedKey = encryptPrivateKey(privateKey);

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store wallet info
  wallets[userId] = {
    address,
    hashedPassword,
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

  return await bcrypt.compare(password, user.hashedPassword);
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
  
  const { hashedPassword, encryptedKey, iv, authTag, ...safeWallet } = wallet;
  return safeWallet;
}

// Get wallet instance for a user (with decrypted private key)
function getWalletInstance(userId, provider) {
  const walletInfo = getWallet(userId);

  if (!walletInfo) {
    return null;
  }

  const privateKey = decryptPrivateKey(
    walletInfo.encryptedKey,
    walletInfo.iv,
    walletInfo.authTag
  );

  return new ethers.Wallet(privateKey, provider);
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
  const highSeverityLogs = logs.filter(l => l.severity === 'high');
  
  // Simple security score calculation
  let score = 100;
  score -= (highSeverityLogs.length * 10);
  
  return {
    score: Math.max(score, 0),
    recentLogs: logs.slice(-5).reverse(),
    status: score > 80 ? 'Secure' : score > 50 ? 'Warning' : 'Critical'
  };
}

// Export functions
module.exports = {
  createWallet,
  getWallet,
  getSafeWallet,
  getWalletInstance,
  listWallets,
  verifyPassword,
  addContact,
  getContactAddress,
  updateGuardrails,
  checkAndUpdateLimit,
  recordTransaction,
  logSecurityEvent,
  getSecurityStatus
};
