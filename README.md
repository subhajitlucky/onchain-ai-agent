# IntentPay: The Intent-Centric Web3 Assistant 🤖⛓️

IntentPay is not just a wallet; it's a **Cognitive Intent Layer** for the blockchain. While MetaMask is a tool for manual execution, this agent understands **human intent**, automates complex workflows, and brings "Web2-level" simplicity to decentralized finance.

![Vision](https://img.shields.io/badge/Vision-Intent--Centric-blueviolet)
![Status](https://img.shields.io/badge/Status-Production--Ready--Roadmap-green)

## 🚀 The 5 Pillars of Real-World Utility

### 1. 🧠 Intent-Centric UX (Beyond Manual Clicks)
MetaMask requires you to know the "how." This agent focuses on the "what."
- **Use Case**: *"Split $100 in ETH between Alice and Bob."*
- **Value**: The agent handles the math, fetches addresses, and prepares the multi-transaction flow.

### 2. 💬 Conversational Commerce & Social Payments
Seamlessly integrate crypto into chat-based environments (Telegram, Discord, Support Bots).
- **Use Case**: *"Pay my share of the dinner to @subhajit."*
- **Value**: Eliminates the friction of switching apps and copying 0x addresses.

### 3. 📊 Complex DeFi Strategy Execution
Automate multi-step DeFi actions that are usually intimidating for non-technical users.
- **Use Case**: *"Move my idle ETH to the highest-yielding stablecoin pool."*
- **Value**: The agent researches, calculates paths, and executes complex swaps/deposits in one sentence.

### 4. 👤 Accessibility & Human-Readable Onboarding
The "0x..." address format is a UX nightmare. We replace it with human handles.
- **Use Case**: *"Send 0.05 ETH to @marketing_team."*
- **Value**: Maps internal handles or ENS names to addresses, making crypto feel like Venmo or CashApp.

### 5. 🛡️ Automated Treasury & Guardrails
Enterprise-grade security for teams and DAOs through programmable constraints.
- **Use Case**: *"Only allow payments to whitelisted vendors up to 1 ETH/day."*
- **Value**: Adds a layer of "Smart Policy" that prevents theft or human error, even if the AI is misinterpreted.

## ✨ Features

- 🧠 **Context-Aware Intelligence**: Powered by OpenRouter (LLM) with real-time injection of user balance, contacts, and guardrails into every decision.
- 🛡️ **Security Health Scoring**: Real-time monitoring of wallet activity with a dynamic security score and event logging.
- ⚔️ **Adversarial Defense**: Hardened system prompts to prevent prompt injection, social engineering, and unauthorized identity changes.
- 🔒 **Safe Wallet Pattern**: Sanitized API layer ensures private keys and password hashes never leave the secure backend logic.
- 🚦 **Smart Guardrails**: Programmable daily spending limits and whitelisting to prevent unauthorized large transfers.
- ⛽ **Gas-Aware Execution**: Robust transaction processing with real-time gas estimation, EIP-1559 support, and detailed error feedback.
- 👥 **Handle & ENS Mapping**: Use names (@handle) or Ethereum Name Service (.eth) instead of addresses.
- 💸 **Natural Language Payments**: Full support for complex, multi-recipient intents and split payments.
- 📊 **Transaction History**: Persistent tracking of all on-chain activity with status badges (Success/Failed) and transaction hashes.
- 🎨 **Modern Glassmorphism UI**: A high-end React dashboard with real-time updates, security badges, and "Thinking" state indicators.

## 🛠️ Architecture

- **Backend**: Node.js + Express.js
- **Blockchain**: Ethers.js v6 (Sepolia Testnet)
- **AI Brain**: OpenRouter API with JSON-based tool-calling and **Dynamic Context Injection**.
- **Security**: AES-256-GCM encryption + bcrypt hashing + **Security Event Logging** + **Sanitized API Responses**.
- **Frontend**: React + Vite + Framer Motion + Lucide Icons + **Real-time Security Monitoring**.

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v18+
- **OpenRouter API Key**: [openrouter.ai](https://openrouter.ai/)
- **Sepolia ETH**: [Alchemy Faucet](https://www.alchemy.com/faucets/ethereum-sepolia)

### Installation
1. **Clone & Install Backend**:
   ```bash
   npm install
   ```
2. **Install Frontend**:
   ```bash
   cd frontend && npm install
   ```

### Configuration (.env)
Create a `.env` file in the root directory:
```env
PORT=3001
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
ENCRYPTION_KEY=your_32_char_random_key_here
OPENROUTER_API_KEY=your_openrouter_key_here
LLM_MODEL=meta-llama/llama-3.1-8b-instruct:free
```

### Running the Project
1. **Start Backend**: `node server.js`
2. **Start Frontend**: `cd frontend && npm run dev`
3. **Access**: Open `http://localhost:5173`

---

> [!TIP]
> **Try these commands in the AI Chat:**
> - *"Remember @alice is 0x742..."*
> - *"Send 0.01 ETH to @alice and 0.02 ETH to vitalik.eth"*
> - *"Set my daily limit to 0.5 ETH"*
> - *"What is my security status?"*
> - *"What is my transaction history?"*

> [!IMPORTANT]
> **Security First**: The agent features a **Real-time Security Badge** in the dashboard. If you see a "Warning" or "Critical" status, check the security logs for suspicious activity or failed login attempts.

## 🗺️ Roadmap to Production

To move from PoC to a Mainnet-ready production environment, we recommend:
1. **HSM/MPC Integration**: Move server-side keys to Hardware Security Modules (AWS KMS or HashiCorp Vault) for the custodial mode.
2. **Account Abstraction (ERC-4337)**: Replace simple EOA wallets with Smart Contract Wallets for better recovery, gas sponsorship, and social recovery.
3. **Multi-Chain Support**: Expand beyond Sepolia to L2s like Base, Arbitrum, and Optimism for lower fees.
4. **Advanced Guardrails**: Implement time-locks and multi-sig requirements for large transactions.

---
