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
  return JSON.parse(fs.readFileSync(WALLETS_FILE, 'utf8'));
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
    createdAt: new Date().toISOString()
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

// Export functions
module.exports = {
  createWallet,
  getWallet,
  getWalletInstance,
  listWallets,
  verifyPassword
};