# Onchain AI Agent 🤖⛓️

Onchain AI Agent is a premium, LLM-powered cryptocurrency payment assistant that combines the ease of modern payment apps (like PhonePe/GPay) with the power of blockchain. It features a secure, password-protected multi-user wallet system and a "thinking" AI brain capable of understanding complex natural language for transaction execution.

![Dashboard Preview](https://img.shields.io/badge/UI-Glassmorphism-blueviolet)
![Chain](https://img.shields.io/badge/Network-Sepolia_Testnet-blue)
![Security](https://img.shields.io/badge/Security-AES--256--GCM-green)

## ✨ Features

- 🧠 **True AI Intelligence**: Powered by OpenRouter (LLM) to understand context, reason through requests, and prevent errors.
- 📱 **Premium UI**: Modern "Glassmorphism" design with real-time balance updates and micro-animations.
- 🔒 **Military-Grade Security**: Private keys are encrypted using AES-256-GCM. User accounts are secured with bcrypt password hashing.
- 💸 **Natural Language Payments**: Just say *"Send 0.001 ETH to 0x..."* and the agent handles the rest.
- 📊 **Real-Time Dashboard**: Monitor your Sepolia ETH balance and manage your secure wallet.
- ⚡ **Streamlined UX**: Direct one-click confirmations for transactions identified by the AI.

## 🚀 Getting Started

### Prerequisites

- **Node.js**: v18 or higher
- **OpenRouter API Key**: Get one at [openrouter.ai](https://openrouter.ai/)
- **Sepolia ETH**: Get some from a faucet (e.g., Alchemy or Google Faucet)

### Installation & Setup

1. **Clone the project & install dependencies**:
   ```bash
   # Install Backend dependencies
   cd onchain-ai-agent
   npm install

   # Install Frontend dependencies
   cd frontend
   npm install
   ```

2. **Configure Environment Variables**:
   Create a `.env` file in the `onchain-ai-agent/` directory:
   ```env
   RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
   ENCRYPTION_KEY=your_32_char_random_key_here
   OPENROUTER_API_KEY=your_openrouter_api_key
   LLM_MODEL=meta-llama/llama-3.1-8b-instruct:free
   PORT=3000
   ```

3. **Start the Engines**:
   ```bash
   # Terminal 1: Start Backend (from onchain-ai-agent/)
   npm start

   # Terminal 2: Start Frontend (from onchain-ai-agent/frontend/)
   npm run dev
   ```

Visit `http://localhost:5173` to access the dashboard.

## 🛠️ Architecture

- **Backend**: Node.js + Express.js
- **Blockchain**: Ethers.js (Sepolia Testnet)
- **AI Brain**: OpenRouter API with JSON-based tool-calling
- **Frontend**: React + Vite + Framer Motion (for animations)
- **Styling**: Vanilla CSS (Premium Glassmorphism Theme)

## 🔒 Security Notes

- User passwords never leave the server in plain text (hashed with bcrypt).
- Private keys are stored in `data/wallets.json` only after being encrypted with your unique `ENCRYPTION_KEY`.
- The AI includes a safety verification step: it will prepare the transaction and ask for your "confirm" before broadcasting to the blockchain.

## 🤝 Contributing

1. Fork the repo.
2. Create your feature branch.
3. Commit your changes.
4. Push to the branch.
5. Create a new Pull Request.

## 📄 License

MIT License - feel free to use for your own projects!

---

> [!CAUTION]
> **Production Disclaimer**: This project is designed as a **Testnet-only** proof of concept. For a production-grade "Mainnet" application handling real significant value, storing private keys in a local filesystem (even if encrypted) is not recommended. Professional implementations should utilize Hardware Security Modules (HSM), Multi-Party Computation (MPC), or non-custodial browser extensions (like MetaMask) where the user maintains full control over their keys.
