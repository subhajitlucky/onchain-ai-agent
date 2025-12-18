import React, { useState, useEffect, useRef } from 'react';
import {
  Wallet,
  Send,
  History,
  MessageSquare,
  User,
  ArrowUpRight,
  ArrowDownLeft,
  Copy,
  CheckCircle2,
  Cpu,
  LogOut,
  Sparkles,
  Lock,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Users
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { ethers } from 'ethers';
import './App.css';

const API_BASE = 'http://localhost:3000/api';
const SEPOLIA_CHAIN_ID = '0xaa36a7'; // 11155111

function App() {
  const [userId, setUserId] = useState(localStorage.getItem('userId') || '');
  const [password, setPassword] = useState(localStorage.getItem('password') || '');
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('userId'));
  const [isSignup, setIsSignup] = useState(false);
  const [wallet, setWallet] = useState(null);
  const [messages, setMessages] = useState([
    { role: 'ai', content: "Hello! I am your AI Crypto Assistant. I can help you manage your wallet and send payments securely." }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [mode, setMode] = useState('custodial'); // 'custodial' or 'non-custodial'
  const [mmAddress, setMmAddress] = useState('');
  const [history, setHistory] = useState([]);
  const [securityStatus, setSecurityStatus] = useState({ score: 100, status: 'Secure', recentLogs: [] });

  const chatEndRef = useRef(null);

  const authHeaders = {
    'x-user-id': userId,
    'x-password': password
  };

  useEffect(() => {
    if (isLoggedIn && userId && password) {
      fetchWallet();
      fetchHistory();
      fetchSecurityStatus();

      // Auto-refresh balance every 30 seconds (conserves RPC quota)
      const poll = setInterval(() => {
        fetchWallet();
        fetchHistory();
        fetchSecurityStatus();
      }, 30000);
      return () => clearInterval(poll);
    }
  }, [isLoggedIn, userId, password]);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
  }, [messages, loading]);

  const fetchWallet = async () => {
    setIsRefreshing(true);
    setLoading(true);
    try {
      const resp = await axios.get(`${API_BASE}/wallet/${userId}`, { headers: authHeaders });
      if (resp.data.success) {
        setWallet(resp.data);
      }
    } catch (err) {
      console.error("Wallet access error", err);
    } finally {
      // Keep spin for at least 800ms for visual satisfaction
      setTimeout(() => {
        setIsRefreshing(false);
        setLoading(false);
      }, 800);
    }
  };

  const fetchHistory = async () => {
    try {
      const resp = await axios.get(`${API_BASE}/history/${userId}`, { headers: authHeaders });
      if (resp.data.success) {
        setHistory(resp.data.transactions);
      }
    } catch (err) {
      console.error("History fetch error", err);
    }
  };

  const fetchSecurityStatus = async () => {
    try {
      const resp = await axios.get(`${API_BASE}/security-status/${userId}`, { headers: authHeaders });
      if (resp.data.success) {
        setSecurityStatus(resp.data);
      }
    } catch (err) {
      console.error("Security status fetch error", err);
    }
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const endpoint = isSignup ? '/signup' : '/login';
      const resp = await axios.post(`${API_BASE}${endpoint}`, { userId, password });

      if (resp.data.success) {
        localStorage.setItem('userId', userId);
        localStorage.setItem('password', password);
        setMessages([{ role: 'ai', content: `Hello ${userId}! I am your AI Crypto Assistant. How can I help you today?` }]);
        setIsLoggedIn(true);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Authentication failed');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('userId');
    localStorage.removeItem('password');
    setUserId('');
    setPassword('');
    setIsLoggedIn(false);
    setWallet(null);
    setMessages([{ role: 'ai', content: "Hello! I am your AI Crypto Assistant. I can help you manage your wallet and send payments securely." }]);
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMsg = input;
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setLoading(true);

    try {
      const resp = await axios.post(`${API_BASE}/chat`, {
        userId,
        message: userMsg,
        mode: mode
      }, { headers: authHeaders });

      if (resp.data.thought) {
        setMessages(prev => [...prev, { role: 'ai', content: `*Thinking: ${resp.data.thought}*` }]);
      }
      setMessages(prev => [...prev, { role: 'ai', content: resp.data.message }]);

      if (resp.data.action === 'sign_required') {
        await signAndSend(resp.data.transactions);
      }

      // Always refresh balance after AI interaction to stay in sync
      fetchWallet();
      fetchHistory();

      if (resp.data.success || resp.data.message.includes('succeeded') || resp.data.message.includes('Hash')) {
        setTimeout(() => {
          fetchWallet();
          fetchHistory();
        }, 3000);
      }
    } catch (err) {
      setMessages(prev => [...prev, { role: 'ai', content: "Authentication error or server down. Try logging in again." }]);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(wallet?.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const connectMetaMask = async () => {
    if (window.ethereum) {
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        
        // Check network immediately
        const currentChainId = await window.ethereum.request({ method: 'eth_chainId' });
        if (currentChainId !== SEPOLIA_CHAIN_ID) {
          try {
            await window.ethereum.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: SEPOLIA_CHAIN_ID }],
            });
          } catch (e) {
            console.warn("Network switch failed on connect, will retry on sign");
          }
        }

        setMmAddress(accounts[0]);
        setMode('non-custodial');
      } catch (err) {
        console.error("MetaMask connection failed", err);
      }
    } else {
      alert("Please install MetaMask!");
    }
  };

  const signAndSend = async (transactions) => {
    if (!window.ethereum) return;
    
    setLoading(true);
    try {
      // 1. Ensure we are on Sepolia
      const currentChainId = await window.ethereum.request({ method: 'eth_chainId' });
      if (currentChainId !== SEPOLIA_CHAIN_ID) {
        try {
          await window.ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: SEPOLIA_CHAIN_ID }],
          });
        } catch (switchError) {
          // This error code indicates that the chain has not been added to MetaMask.
          if (switchError.code === 4902) {
            await window.ethereum.request({
              method: 'wallet_addEthereumChain',
              params: [
                {
                  chainId: SEPOLIA_CHAIN_ID,
                  chainName: 'Sepolia Test Network',
                  nativeCurrency: { name: 'Sepolia ETH', symbol: 'ETH', decimals: 18 },
                  rpcUrls: ['https://ethereum-sepolia-rpc.publicnode.com'],
                  blockExplorerUrls: ['https://sepolia.etherscan.io'],
                },
              ],
            });
          } else {
            throw switchError;
          }
        }
      }

      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();

      for (const tx of transactions) {
        const txResponse = await signer.sendTransaction({
          to: tx.to,
          value: tx.value
        });
        setMessages(prev => [...prev, { role: 'ai', content: `Transaction sent! Hash: ${txResponse.hash}` }]);
        
        // Record in backend history
        await axios.post(`${API_BASE}/record-tx`, {
          userId,
          tx: {
            type: 'send',
            to: tx.to,
            amount: ethers.formatEther(tx.value),
            hash: txResponse.hash,
            status: 'success',
            mode: 'non-custodial'
          }
        }, { headers: authHeaders });

        await txResponse.wait();
      }
      setMessages(prev => [...prev, { role: 'ai', content: "All transactions confirmed on-chain! 🎉" }]);
    } catch (err) {
      console.error("MetaMask Error:", err);
      setMessages(prev => [...prev, { role: 'ai', content: `MetaMask Error: ${err.message}` }]);
    } finally {
      setLoading(false);
      fetchWallet();
      fetchHistory();
    }
  };

  if (!isLoggedIn) {
    return (
      <div className="auth-container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card"
          style={{ width: '400px' }}
        >
          <div style={{ textAlign: 'center', marginBottom: '32px' }}>
            <div className="btn" style={{ width: '64px', height: '64px', margin: '0 auto 16px', borderRadius: '20px' }}>
              <Lock size={32} />
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: '800' }}>Onchain AI Agent</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>Secure Wallet Access</p>
          </div>

          <form onSubmit={handleAuth}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '600' }}>Username</label>
            <input
              type="text"
              className="input-field"
              placeholder="Username"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              required
            />
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '600' }}>Password</label>
            <input
              type="password"
              className="input-field"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {error && <p style={{ color: '#ef4444', fontSize: '12px', marginBottom: '16px' }}>{error}</p>}
            <button type="submit" className="btn" style={{ width: '100%', marginTop: '8px' }}>
              {isSignup ? 'Create Account' : 'Login'}
            </button>
          </form>
          <p style={{ textAlign: 'center', marginTop: '16px', fontSize: '14px', color: 'var(--text-muted)' }}>
            {isSignup ? 'Already have a wallet?' : 'Need a new wallet?'}
            <span
              onClick={() => setIsSignup(!isSignup)}
              style={{ color: 'var(--primary)', cursor: 'pointer', marginLeft: '8px', fontWeight: '600' }}
            >
              {isSignup ? 'Login' : 'Sign Up'}
            </span>
          </p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h2 style={{ fontSize: '14px', color: 'var(--text-muted)' }}>Secure Wallet of</h2>
          <h1 style={{ fontSize: '20px', fontWeight: '700' }}>{userId}</h1>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button 
            onClick={connectMetaMask} 
            className="btn" 
            style={{ 
              padding: '8px 16px', 
              background: mmAddress ? 'rgba(74, 222, 128, 0.1)' : 'var(--glass)',
              color: mmAddress ? '#4ade80' : 'inherit',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            <Wallet size={16} />
            {mmAddress ? `${mmAddress.substring(0, 6)}...` : 'Connect MetaMask'}
          </button>
          <button onClick={handleLogout} className="btn" style={{ padding: '8px', background: 'var(--glass)' }}>
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        <button 
          onClick={() => setMode('custodial')}
          className={`btn ${mode === 'custodial' ? 'active' : ''}`}
          style={{ flex: 1, fontSize: '12px', background: mode === 'custodial' ? 'var(--primary)' : 'var(--glass)' }}
        >
          <ShieldCheck size={14} style={{ marginRight: '8px' }} />
          Custodial (Server)
        </button>
        <button 
          onClick={() => setMode('non-custodial')}
          className={`btn ${mode === 'non-custodial' ? 'active' : ''}`}
          style={{ flex: 1, fontSize: '12px', background: mode === 'non-custodial' ? 'var(--primary)' : 'var(--glass)' }}
        >
          <ShieldAlert size={14} style={{ marginRight: '8px' }} />
          Non-Custodial (MetaMask)
        </button>
      </div>

      <motion.div
        layoutId="balance"
        className="balance-card floating"
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={16} color={securityStatus.score > 80 ? '#4ade80' : '#fbbf24'} />
            <span style={{ fontSize: '12px', fontWeight: '600', color: securityStatus.score > 80 ? '#4ade80' : '#fbbf24' }}>
              Security: {securityStatus.status} ({securityStatus.score}%)
            </span>
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
            Sepolia Testnet
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '14px', opacity: 0.8 }}>Total Balance</span>
          <button
            onClick={fetchWallet}
            className="btn"
            style={{ padding: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '6px' }}
            title="Refresh Balance"
          >
            <RefreshCw
              size={14}
              style={{
                animation: isRefreshing ? 'spin 1s linear infinite' : 'none',
                opacity: isRefreshing ? 0.5 : 1
              }}
            />
          </button>
        </div>
        <div className="balance-amount">
          {wallet ? `${parseFloat(wallet.balance).toFixed(4)} ETH` : '0.0000 ETH'}
        </div>

        {wallet?.address && (
          <div className="address-badge" onClick={copyToClipboard}>
            <span>{wallet.address.substring(0, 10)}...{wallet.address.substring(34)}</span>
            {copied ? <CheckCircle2 size={14} color="#4ade80" /> : <Copy size={14} />}
          </div>
        )}
      </motion.div>

      {wallet?.contacts && Object.keys(wallet.contacts).length > 0 && (
        <div className="glass-card" style={{ padding: '16px', marginBottom: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Users size={16} color="var(--primary)" />
            <span style={{ fontSize: '14px', fontWeight: '600' }}>Contacts</span>
          </div>
          <div style={{ display: 'flex', gap: '8px', overflowX: 'auto', paddingBottom: '4px' }}>
            {Object.entries(wallet.contacts).map(([handle, addr]) => (
              <div 
                key={handle} 
                title={addr}
                style={{ 
                  background: 'var(--glass)', 
                  padding: '6px 12px', 
                  borderRadius: '20px', 
                  fontSize: '12px',
                  border: '1px solid var(--glass-border)',
                  whiteSpace: 'nowrap',
                  cursor: 'help'
                }}
              >
                {handle}
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '32px' }}>
        <div className="glass-card" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="btn" style={{ padding: '8px', borderRadius: '10px' }}>
            <ArrowUpRight size={18} />
          </div>
          <span style={{ fontSize: '14px', fontWeight: '600' }}>Send</span>
        </div>
        <div className="glass-card" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="btn" style={{ padding: '8px', borderRadius: '10px', background: 'var(--secondary)' }}>
            <ArrowDownLeft size={18} />
          </div>
          <span style={{ fontSize: '14px', fontWeight: '600' }}>Receive</span>
        </div>
      </div>

      <div className="glass-card" style={{ padding: '24px', flex: 1, marginBottom: '100px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <History size={18} color="var(--primary)" />
          <h3 style={{ fontSize: '16px' }}>Transaction History</h3>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '300px', overflowY: 'auto' }}>
          {history.length > 0 ? (
            history.map((tx, i) => (
              <div key={i} className="history-item">
                <div className="history-info">
                  <span className="history-type" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    {tx.type === 'send' ? <ArrowUpRight size={14} /> : <ArrowDownLeft size={14} />}
                    {tx.type.toUpperCase()}
                  </span>
                  <span className="history-amount">{tx.amount} ETH</span>
                </div>
                <div className="history-details">
                  <span title={tx.to}>
                    To: {tx.to.startsWith('@') ? tx.to : `${tx.to.substring(0, 6)}...${tx.to.substring(38)}`}
                  </span>
                  <span className={`status-badge ${tx.status || 'success'}`}>
                    {tx.status || 'success'}
                  </span>
                </div>
                {tx.hash && (
                  <div style={{ fontSize: '9px', marginTop: '4px', opacity: 0.5, fontFamily: 'monospace' }}>
                    Hash: {tx.hash.substring(0, 20)}...
                  </div>
                )}
                {tx.error && (
                  <div style={{ fontSize: '9px', marginTop: '4px', color: '#f87171', fontStyle: 'italic' }}>
                    Error: {tx.error}
                  </div>
                )}
              </div>
            ))
          ) : (
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', textAlign: 'center' }}>No transactions yet.</p>
          )}
        </div>
      </div>

      {/* AI Assistant Drawer */}
      <div className="ai-assistant">
        <div className="chat-window">
          <div className="chat-header">
            <div className="btn" style={{ padding: '6px', borderRadius: '8px' }}>
              <Cpu size={16} />
            </div>
            <div>
              <h4 style={{ fontSize: '14px' }}>Onchain AI Agent</h4>
              <span style={{ fontSize: '10px', color: '#4ade80' }}>Secured Path</span>
            </div>
          </div>

          <div className="chat-messages">
            {messages.map((m, i) => (
              <div key={i} className={`message ${m.role}`}>
                {m.content}
              </div>
            ))}
            {loading && <div className="message ai">...</div>}
            <div ref={chatEndRef} />
          </div>

          <form onSubmit={sendMessage} className="chat-input-area">
            <input
              type="text"
              className="input-field"
              style={{ marginBottom: 0 }}
              placeholder="Ask AI to send ETH..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
            <button type="submit" className="btn" style={{ padding: '10px' }}>
              <Send size={18} />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default App;
