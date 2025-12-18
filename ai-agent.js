const { ethers } = require('ethers');
const axios = require('axios');
const walletManager = require('./wallet-manager');
require('dotenv').config();

// Initialize provider
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);

// OpenRouter Config
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const LLM_MODEL = process.env.LLM_MODEL || 'meta-llama/llama-3.1-8b-instruct:free';

// Session storage for context
const userSessions = {};

const SYSTEM_PROMPT = `
You are "Onchain AI Agent", a high-end AI Crypto Assistant. Your goal is to help users manage their Ethereum wallets and make payments securely.

You have access to specific tools. If a user wants to perform an action, you MUST respond with a JSON object in the following format:
{
  "thought": "Brief explanation of why you are taking this action",
  "action": "ACTION_NAME",
  "params": { ...required parameters... }
}

AVAILABLE ACTIONS:
1. "getBalance": Check the user's current ETH balance. (No params)
2. "getAddress": Show the user's public Ethereum address. (No params)
3. "sendEth": Transfer ETH to another address. REQUIRED PARAMS: "recipient" (0x address) and "amount" (number in ETH).
4. "explain": Use this to explain crypto concepts if you don't need to call a tool.

GUIDELINES:
- If a user says "send 0.1 ETH to 0x...", call "sendEth".
- If a user asks for their balance or how much they have, call "getBalance".
- If the user is just chatting or asking a general question, just reply with text.
- NEVER ask for private keys or passwords.
- All transactions are on the Sepolia Testnet.
- If you call an action, do NOT include any other text in your response, ONLY the JSON.
- CRITICAL: When the user provides an Ethereum address (0x...), you MUST copy it EXACTLY character-for-character. Any deviation will cause the transaction to fail.
`;

/**
 * Call OpenRouter LLM
 */
async function callLLM(userId, message, session) {
  try {
    if (!OPENROUTER_API_KEY || OPENROUTER_API_KEY === 'your_openrouter_key_here') {
      return { action: 'error', message: "API Key Missing: Please add your OPENROUTER_API_KEY to the .env file to enable the Intelligence upgrade." };
    }

    // Keep last 10 messages for context
    const history = (session.history || []).slice(-10);

    const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: LLM_MODEL,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        ...history,
        { role: 'user', content: message }
      ],
      response_format: { type: 'json_object' }
    }, {
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://crypto-ai-agent-pay.com', // Optional
        'X-Title': 'Onchain AI Agent'
      }
    });

    const aiContent = response.data.choices[0].message.content;

    // Update history
    if (!session.history) session.history = [];
    session.history.push({ role: 'user', content: message });
    session.history.push({ role: 'assistant', content: aiContent });

    return JSON.parse(aiContent);
  } catch (error) {
    console.error("LLM Error:", error.response?.data || error.message);
    return { action: 'text', message: "I'm having trouble thinking right now. Please check my API connection." };
  }
}

/**
 * Process natural language commands using LLM
 */
async function processCommand(userId, message, sessionId = null) {
  const session = getOrCreateSession(userId, sessionId);

  // 1. Check for manual 'confirm' if a transaction was pending
  if (session.state && session.state.pendingTx && /confirm|yes|proceed/i.test(message)) {
    const result = await executeSendEth(userId, session.state.pendingTx.recipient, session.state.pendingTx.amount);
    session.state = {}; // Clear state
    return result;
  }

  // 2. Call the LLM to decide the action
  const decision = await callLLM(userId, message, session);

  // 3. Execute the resulting action
  switch (decision.action) {
    case 'getBalance':
      return await handleGetBalance(userId);

    case 'getAddress':
      return await handleGetAddress(userId);

    case 'sendEth':
      return await startSendEthProcess(userId, session, decision.params);

    case 'explain':
    case 'text':
    default:
      return { success: true, message: decision.message || decision.content || "I understand. How else can I help?" };
  }
}

/**
 * Get or create user session
 */
function getOrCreateSession(userId, sessionId = null) {
  const sessionKey = sessionId || userId;
  if (!userSessions[sessionKey]) {
    userSessions[sessionKey] = {
      userId,
      createdAt: new Date().toISOString(),
      state: {},
      history: []
    };
  }
  return userSessions[sessionKey];
}

/**
 * Tools / Action Handlers
 */

async function handleGetAddress(userId) {
  const wallet = walletManager.getWallet(userId);
  if (!wallet) return { success: false, message: "You don't have a wallet yet. Please sign up." };
  return { success: true, message: `Your Ethereum wallet address is: ${wallet.address}` };
}

async function handleGetBalance(userId) {
  const wallet = walletManager.getWallet(userId);
  if (!wallet) return { success: false, message: "No wallet found." };

  try {
    const balance = await provider.getBalance(wallet.address);
    return { success: true, message: `Your balance is currently ${ethers.formatEther(balance)} ETH.` };
  } catch (err) {
    return { success: false, message: "Error checking balance." };
  }
}

async function startSendEthProcess(userId, session, params) {
  const wallet = walletManager.getWallet(userId);
  if (!wallet) return { success: false, message: "No wallet found." };

  const { recipient, amount } = params;
  if (!recipient || !amount) return { success: false, message: "I need both an address and an amount to send ETH." };

  // Store for confirmation
  session.state.pendingTx = { recipient, amount: amount.toString() };

  return {
    success: true,
    message: `I've prepared a transaction to send ${amount} ETH to ${recipient}. Should I proceed? Type "confirm" to send.`
  };
}

async function executeSendEth(userId, recipient, amount) {
  try {
    // Validate address format before sending
    if (!ethers.isAddress(recipient)) {
      return {
        success: false,
        message: `Transaction failed: The address "${recipient}" is not a valid Ethereum address. Please check for typos and try again.`
      };
    }

    const walletInstance = walletManager.getWalletInstance(userId, provider);
    const tx = await walletInstance.sendTransaction({
      to: recipient,
      value: ethers.parseEther(amount),
      gasLimit: 21000
    });
    return { success: true, message: `Transaction sent successfully! Hash: ${tx.hash}`, txHash: tx.hash };
  } catch (error) {
    return { success: false, message: `Transaction failed: ${error.message}` };
  }
}

module.exports = { processCommand, provider };