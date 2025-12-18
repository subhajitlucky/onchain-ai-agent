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
  RefreshCw
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import './App.css';

const API_BASE = 'http://localhost:3000/api';

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

  const chatEndRef = useRef(null);

  const authHeaders = {
    'x-user-id': userId,
    'x-password': password
  };

  useEffect(() => {
    if (isLoggedIn && userId && password) {
      fetchWallet();

      // Auto-refresh balance every 30 seconds (conserves RPC quota)
      const poll = setInterval(fetchWallet, 30000);
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
        message: userMsg
      }, { headers: authHeaders });

      setMessages(prev => [...prev, { role: 'ai', content: resp.data.message }]);

      // Always refresh balance after AI interaction to stay in sync
      fetchWallet();

      if (resp.data.message.includes('created') || resp.data.message.includes('Transaction sent')) {
        setTimeout(fetchWallet, 2000);
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
        <button onClick={handleLogout} className="btn" style={{ padding: '8px', background: 'var(--glass)' }}>
          <LogOut size={18} />
        </button>
      </header>

      <motion.div
        layoutId="balance"
        className="balance-card floating"
      >
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
          <h3 style={{ fontSize: '16px' }}>Quick Actions</h3>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {['Check Gas Prices', 'What is Ethereum?', 'Show my address'].map((action, i) => (
            <button
              key={i}
              className="input-field"
              style={{ marginBottom: 0, textAlign: 'left', cursor: 'pointer' }}
              onClick={() => { setInput(action); }}
            >
              {action}
            </button>
          ))}
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
