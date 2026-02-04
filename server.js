const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { ethers } = require('ethers');
const { v4: uuidv4 } = require('uuid');
const { processCommand, provider } = require('./ai-agent');
const walletManager = require('./wallet-manager');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Validate essential env vars on startup
const REQUIRED_ENV = ['RPC_URL', 'ENCRYPTION_KEY', 'OPENROUTER_API_KEY'];
REQUIRED_ENV.forEach(key => {
  if (!process.env[key]) {
    console.error(`FATAL: Missing required environment variable: ${key}`);
    process.exit(1);
  }
});

// Middleware
app.use(helmet()); // Basic security headers
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting to prevent brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 requests per window
  message: { success: false, message: 'Too many attempts, please try again later.' }
});

const chatLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // Limit each IP to 30 chat messages per minute
  message: { success: false, message: 'Slow down! Too many messages.' }
});

// Authentication middleware
async function authenticateUser(req, res, next) {
  const userId = req.headers['x-user-id'] || req.body.userId || req.params.userId;
  const password = req.headers['x-password'];

  if (!userId) {
    return res.status(401).json({ success: false, message: 'User ID is required' });
  }

  // Check if user exists
  const wallet = walletManager.getWallet(userId);
  if (!wallet) {
    // If user doesn't exist, we allow it (for signup/first chat)
    return next();
  }

  // If user exists, they must provide a password
  if (!password) {
    return res.status(401).json({ success: false, message: 'Password is required' });
  }

  const isValid = await walletManager.verifyPassword(userId, password);
  if (!isValid) {
    return res.status(401).json({ success: false, message: 'Invalid password' });
  }

  next();
}

// Signup endpoint
app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    const { userId, password } = req.body;
    if (!userId || !password) {
      return res.status(400).json({ success: false, message: 'UserId and password required' });
    }
    const result = await walletManager.createWallet(userId, password);
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Login endpoint
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { userId, password } = req.body;
    const isValid = await walletManager.verifyPassword(userId, password);
    if (isValid) {
      const wallet = walletManager.getWallet(userId);
      res.json({ success: true, userId, address: wallet.address });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

/**
 * API Routes
 */

// Chat endpoint - process user messages and manage session state
app.post('/api/chat', [authenticateUser, chatLimiter], async (req, res) => {
  try {
    const { userId, message, sessionId, mode } = req.body;

    if (!userId || !message) {
      return res.status(400).json({
        success: false,
        message: 'Both userId and message are required'
      });
    }

    // Process the message through the AI agent
    const password = req.headers['x-password'];
    const result = await processCommand(userId, message, sessionId, mode || 'custodial', password);

    // Respond with the result
    res.json(result);
  } catch (error) {
    console.error('Error processing chat message:', error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`
    });
  }
});

// Get wallet info (addresses and balances)
app.get('/api/wallet/:userId', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    const wallet = walletManager.getSafeWallet(userId);

    if (!wallet) {
      return res.status(404).json({
        success: false,
        message: 'No wallet found for this user'
      });
    }

    // Get the wallet's balance
    const balance = await provider.getBalance(wallet.address);

    res.json({
      success: true,
      ...wallet,
      balance: ethers.formatEther(balance),
      balanceWei: balance.toString()
    });
  } catch (error) {
    console.error('Error getting wallet info:', error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`
    });
  }
});

// Create a new wallet
app.post('/api/wallet/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { password } = req.body;
    const result = await walletManager.createWallet(userId, password);

    res.json(result);
  } catch (error) {
    console.error('Error creating wallet:', error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`
    });
  }
});

// Send ETH to a recipient
app.post('/api/transaction/:userId', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    const { recipient, amount } = req.body;

    if (!recipient || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Both recipient and amount are required'
      });
    }

    // Validate address
    if (!ethers.isAddress(recipient)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid recipient address'
      });
    }

    // Validate amount
    const amountFloat = parseFloat(amount);
    if (isNaN(amountFloat) || amountFloat <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be a positive number'
      });
    }

    // Get wallet instance
    const password = req.headers['x-password'];
    const walletInstance = walletManager.getWalletInstance(userId, provider, password);

    if (!walletInstance) {
      return res.status(404).json({
        success: false,
        message: 'No wallet found for this user'
      });
    }

    // Check balance
    const balance = await walletInstance.getBalance();
    const amountWei = ethers.parseEther(amount.toString());

    if (balance.lt(amountWei)) {
      return res.status(400).json({
        success: false,
        message: `Insufficient balance. You have ${ethers.formatEther(balance)} ETH, trying to send ${amount} ETH`
      });
    }

    // Check Guardrails (Daily Limit)
    const allowed = walletManager.checkAndUpdateLimit(userId, amount);
    if (!allowed) {
      return res.status(400).json({
        success: false,
        message: 'Daily limit exceeded'
      });
    }

    // Send transaction
    const tx = await walletInstance.sendTransaction({
      to: recipient,
      value: amountWei,
      gasLimit: 21000 // Standard gas limit for ETH transfers
    });

    // Record transaction
    walletManager.recordTransaction(userId, {
      type: 'send',
      to: recipient,
      amount: amount,
      hash: tx.hash,
      status: 'success',
      mode: 'custodial'
    });

    res.json({
      success: true,
      txHash: tx.hash,
      from: walletInstance.address,
      to: recipient,
      amount
    });
  } catch (error) {
    console.error('Error sending transaction:', error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`
    });
  }
});


// Get transaction history
app.get('/api/history/:userId', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    const wallet = walletManager.getSafeWallet(userId);

    if (!wallet) {
      return res.status(404).json({
        success: false,
        message: 'No wallet found for this user'
      });
    }

    res.json({
      success: true,
      transactions: wallet.transactions || []
    });
  } catch (error) {
    console.error('Error getting history:', error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`
    });
  }
});

// Record a transaction (useful for non-custodial mode)
app.post('/api/record-tx', authenticateUser, async (req, res) => {
  try {
    const { userId, tx } = req.body;
    walletManager.recordTransaction(userId, tx);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get security status
app.get('/api/security-status/:userId', authenticateUser, (req, res) => {
  try {
    const { userId } = req.params;
    const status = walletManager.getSecurityStatus(userId);
    res.json({ success: true, ...status });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Basic health check
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'Onchain AI Agent is active' });
});

// Serve a simple home page
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Onchain AI Agent</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
          }
          h1 {
            color: #333;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
          }
          .endpoint {
            background: #f5f5f5;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
          }
          .method {
            font-weight: bold;
            color: #0066cc;
          }
          code {
            background: #eee;
            padding: 2px 5px;
            border-radius: 3px;
          }
        </style>
      </head>
      <body>
        <h1>Onchain AI Agent API</h1>
        
        <p>Welcome to the Multi-User Wallet AI Agent API. Below are the available endpoints:</p>
        
        <div class="endpoint">
          <p><span class="method">POST</span> /api/chat</p>
          <p>Process natural language commands and interact with the wallet agent.</p>
          <p>Required parameters: <code>userId</code>, <code>message</code></p>
          <p>Optional parameters: <code>sessionId</code></p>
        </div>
        
        <div class="endpoint">
          <p><span class="method">GET</span> /api/wallet/:userId</p>
          <p>Get wallet information including address and balance.</p>
        </div>
        
        <div class="endpoint">
          <p><span class="method">POST</span> /api/wallet/:userId</p>
          <p>Create a new wallet for the specified user.</p>
        </div>
        
        <div class="endpoint">
          <p><span class="method">POST</span> /api/transaction/:userId</p>
          <p>Send ETH from the user's wallet to a specified address.</p>
          <p>Required parameters: <code>recipient</code>, <code>amount</code></p>
        </div>
        
        <p>For more information, please refer to the documentation.</p>
      </body>
    </html>
  `);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`RPC URL: ${process.env.RPC_URL.substring(0, 20)}...`);
  console.log(`Visit http://localhost:${PORT} to view the API documentation`);
}); 