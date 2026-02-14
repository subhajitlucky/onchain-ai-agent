import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
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
  Users,
  Volume2,
  VolumeX,
  Mic,
  MicOff
} from 'lucide-react';
import axios from 'axios';
import { ethers } from 'ethers';
import { API_BASE } from './config/api';
import './App.css';

const SEPOLIA_CHAIN_ID = '0xaa36a7'; // 11155111
const CHAT_HISTORY_PREFIX = 'onchain_chat_history_';
const MAX_STORED_MESSAGES = 200;

function extractResetSecret(message) {
  if (!message || typeof message !== 'string') return '';
  const match = message.match(/^\s*(?:reset|change)\s+(?:pin|password)\s+(?:to\s+)?(.+?)\s*$/i);
  return match?.[1]?.trim() || '';
}

function getDefaultGreeting(name = '') {
  if (name) {
    return `Hello ${name}! I am IntentPay Assistant. How can I help you today?`;
  }
  return "Hello! I am IntentPay Assistant. I can help you manage your wallet and send payments securely.";
}

function getChatStorageKey(userId) {
  return `${CHAT_HISTORY_PREFIX}${userId || 'anonymous'}`;
}

function redactSensitiveContent(content) {
  if (typeof content !== 'string') return content;
  const trimmed = content.trim();

  if (/^(?:confirm|yes|proceed)\s+.+/i.test(trimmed)) {
    const cmd = trimmed.split(/\s+/)[0];
    return `${cmd} [REDACTED]`;
  }

  if (/^(?:set|change|reset)\s+(?:payment\s+)?(?:pin|password|secret|secret\s+word)\s+(?:to\s+)?/i.test(trimmed)) {
    return trimmed.replace(
      /^(.*?\b(?:to)\b\s*).+$/i,
      '$1[REDACTED]'
    ).replace(
      /^(.*?\b(?:pin|password|secret|secret\s+word)\b\s*).+$/i,
      '$1[REDACTED]'
    );
  }

  if (/^(?:reset|change)\s+(?:pin|password)\s+(?:to\s+)?/i.test(trimmed)) {
    return trimmed.replace(/^(.*?\b(?:to)\b\s*).+$/i, '$1[REDACTED]');
  }

  if (/(seed phrase|private key)/i.test(trimmed)) {
    return trimmed.replace(/(seed phrase|private key)(\s*[:=]?\s*).+/i, '$1$2[REDACTED]');
  }

  return content;
}

function sanitizeMessagesForStorage(messages) {
  return messages.map((m) => ({
    role: m.role,
    content: redactSensitiveContent(m.content)
  }));
}

function App() {
  const [userId, setUserId] = useState(localStorage.getItem('userId') || '');
  const [authToken, setAuthToken] = useState(localStorage.getItem('authToken') || '');
  const [password, setPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(!!(localStorage.getItem('userId') && localStorage.getItem('authToken')));
  const [isSignup, setIsSignup] = useState(false);
  const [wallet, setWallet] = useState(null);
  const [messages, setMessages] = useState([
    { role: 'ai', content: getDefaultGreeting() }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastRefreshAt, setLastRefreshAt] = useState(null);
  const [refreshError, setRefreshError] = useState('');
  const [mode, setMode] = useState('custodial'); // 'custodial' or 'non-custodial'
  const [mmAddress, setMmAddress] = useState('');
  const [history, setHistory] = useState([]);
  const [securityStatus, setSecurityStatus] = useState({ score: 100, status: 'Secure', recentLogs: [] });
  const [voiceEnabled, setVoiceEnabled] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [voiceHintDismissed, setVoiceHintDismissed] = useState(false);

  const chatEndRef = useRef(null);
  const spokenMessageCountRef = useRef(0);
  const speechRecognitionRef = useRef(null);
  const speechDraftRef = useRef('');
  const voiceEngineRef = useRef(null);
  const refreshInFlightRef = useRef(false);
  const sessionCheckedRef = useRef(false);

  const authHeaders = useMemo(() => ({
    'x-user-id': userId,
    ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    ...(!authToken && password ? { 'x-password': password } : {})
  }), [userId, authToken, password]);

  const canUseSpeech = typeof window !== 'undefined' && 'speechSynthesis' in window;
  const canUseNativeSpeechToText = typeof window !== 'undefined' && (
    'webkitSpeechRecognition' in window || 'SpeechRecognition' in window
  );
  const canUseWhisperSpeechToText = typeof window !== 'undefined'
    && !!navigator.mediaDevices?.getUserMedia
    && !!(window.AudioContext || window.webkitAudioContext);
  const canUseSpeechToText = canUseNativeSpeechToText || canUseWhisperSpeechToText;

  const stopSpeaking = useCallback(() => {
    if (!canUseSpeech) return;
    window.speechSynthesis.cancel();
  }, [canUseSpeech]);

  const speakText = useCallback((text) => {
    if (!canUseSpeech || !text) return;
    const utterance = new SpeechSynthesisUtterance(String(text));
    utterance.rate = 1;
    utterance.pitch = 1;
    stopSpeaking();
    window.speechSynthesis.speak(utterance);
  }, [canUseSpeech, stopSpeaking]);

  const clearAuthAndReturnToLogin = useCallback((message = '') => {
    sessionCheckedRef.current = false;
    localStorage.removeItem('userId');
    localStorage.removeItem('authToken');
    setUserId('');
    setAuthToken('');
    setPassword('');
    setIsLoggedIn(false);
    setWallet(null);
    setHistory([]);
    setSecurityStatus({ score: 100, status: 'Secure', recentLogs: [] });
    setLastRefreshAt(null);
    setRefreshError('');
    setMessages([{ role: 'ai', content: getDefaultGreeting() }]);
    if (message) setError(message);
  }, []);

  const refreshDashboard = useCallback(async (manual = false) => {
    if (refreshInFlightRef.current) return;
    refreshInFlightRef.current = true;
    setIsRefreshing(true);
    setRefreshError('');

    const headers = authHeaders;

    try {
      const [walletRes, historyRes, securityRes] = await Promise.allSettled([
        axios.get(`${API_BASE}/wallet/${userId}`, { headers }),
        axios.get(`${API_BASE}/history/${userId}`, { headers }),
        axios.get(`${API_BASE}/security-status/${userId}`, { headers })
      ]);

      const issues = [];
      const unauthorized = [walletRes, historyRes, securityRes].some(
        (r) => r.status === 'rejected' && r.reason?.response?.status === 401
      );
      if (unauthorized) {
        clearAuthAndReturnToLogin('Session expired. Please log in again.');
        return;
      }
      let refreshedAnything = false;

      if (walletRes.status === 'fulfilled' && walletRes.value?.data?.success) {
        setWallet(walletRes.value.data);
        refreshedAnything = true;
      } else {
        issues.push(walletRes.reason?.response?.data?.message || 'Wallet refresh failed');
      }

      if (historyRes.status === 'fulfilled' && historyRes.value?.data?.success) {
        setHistory(historyRes.value.data.transactions || []);
        refreshedAnything = true;
      } else {
        issues.push(historyRes.reason?.response?.data?.message || 'History refresh failed');
      }

      if (securityRes.status === 'fulfilled' && securityRes.value?.data?.success) {
        setSecurityStatus(securityRes.value.data);
        refreshedAnything = true;
      } else {
        issues.push(securityRes.reason?.response?.data?.message || 'Security refresh failed');
      }

      if (refreshedAnything) {
        setLastRefreshAt(new Date());
      }

      if (issues.length > 0) {
        const firstIssue = issues[0];
        setRefreshError(firstIssue);
        if (manual) {
          setMessages(prev => [...prev, { role: 'ai', content: `Refresh warning: ${firstIssue}` }]);
        }
      }
    } catch (err) {
      console.error("Manual refresh error", err);
      const msg = err.response?.data?.message || 'Refresh failed';
      setRefreshError(msg);
      if (manual) {
        setMessages(prev => [...prev, { role: 'ai', content: `Refresh failed: ${msg}` }]);
      }
    } finally {
      refreshInFlightRef.current = false;
      setIsRefreshing(false);
    }
  }, [authHeaders, userId, clearAuthAndReturnToLogin]);

  useEffect(() => {
    localStorage.removeItem('password');
    if (localStorage.getItem('userId') && !localStorage.getItem('authToken')) {
      localStorage.removeItem('userId');
      setUserId('');
      setIsLoggedIn(false);
    }
  }, []);

  useEffect(() => {
    if (!isLoggedIn || !userId || !authToken || sessionCheckedRef.current) return;

    sessionCheckedRef.current = true;
    axios.get(`${API_BASE}/auth/me`, { headers: authHeaders })
      .catch(() => {
        clearAuthAndReturnToLogin('Session expired. Please log in again.');
      });
  }, [isLoggedIn, userId, authToken, authHeaders, clearAuthAndReturnToLogin]);

  useEffect(() => {
    if (!isLoggedIn || !userId) {
      setMessages([{ role: 'ai', content: getDefaultGreeting() }]);
      return;
    }

    try {
      const raw = localStorage.getItem(getChatStorageKey(userId));
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          setMessages(parsed);
          return;
        }
      }
    } catch (err) {
      console.error('Failed to load stored chat history', err);
    }

    setMessages([{ role: 'ai', content: getDefaultGreeting(userId) }]);
  }, [isLoggedIn, userId]);

  useEffect(() => {
    if (!isLoggedIn || !userId) return;
    try {
      const limited = messages.slice(-MAX_STORED_MESSAGES);
      const sanitized = sanitizeMessagesForStorage(limited);
      localStorage.setItem(getChatStorageKey(userId), JSON.stringify(sanitized));
    } catch (err) {
      console.error('Failed to persist chat history', err);
    }
  }, [messages, isLoggedIn, userId]);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
  }, [messages, loading]);

  useEffect(() => {
    if (!voiceEnabled || !canUseSpeech) {
      spokenMessageCountRef.current = messages.length;
      return;
    }
    if (messages.length <= spokenMessageCountRef.current) return;

    const incoming = messages.slice(spokenMessageCountRef.current);
    const latestAi = [...incoming].reverse().find(
      (m) => m.role === 'ai' && typeof m.content === 'string' && m.content.trim() && !m.content.startsWith('*Thinking:')
    );
    if (latestAi) speakText(latestAi.content);
    spokenMessageCountRef.current = messages.length;
  }, [messages, voiceEnabled, canUseSpeech, speakText]);

  useEffect(() => {
    return () => stopSpeaking();
  }, [stopSpeaking]);

  useEffect(() => {
    return () => {
      if (speechRecognitionRef.current) {
        speechRecognitionRef.current.onresult = null;
        speechRecognitionRef.current.onerror = null;
        speechRecognitionRef.current.onend = null;
        try {
          speechRecognitionRef.current.stop();
        } catch {
          // no-op during unmount cleanup
        }
      }

      if (voiceEngineRef.current) {
        try {
          voiceEngineRef.current.stopAndTranscribe();
        } catch {
          // no-op during unmount cleanup
        }
      }
    };
  }, []);

  const handleAuth = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const endpoint = isSignup ? '/signup' : '/login';
      const resp = await axios.post(`${API_BASE}${endpoint}`, { userId, password });

      if (resp.data.success) {
        const token = resp.data.token;
        if (!token) {
          setError('Authentication failed: server did not return a session token. Please restart backend and login again.');
          setIsLoggedIn(false);
          return;
        }
        localStorage.setItem('userId', userId);
        localStorage.setItem('authToken', token);
        setAuthToken(token);
        sessionCheckedRef.current = false;
        setPassword('');
        setIsLoggedIn(true);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Authentication failed');
    }
  };

  const handleLogout = () => {
    if (authToken) {
      axios.post(`${API_BASE}/logout`, {}, { headers: authHeaders }).catch(() => {});
    }
    clearAuthAndReturnToLogin();
  };

  const clearChatHistory = () => {
    if (!userId) return;
    localStorage.removeItem(getChatStorageKey(userId));
    setMessages([{ role: 'ai', content: getDefaultGreeting(userId) }]);
  };

  const submitUserMessage = async (rawMessage) => {
    if (!rawMessage || !String(rawMessage).trim()) return;
    const userMsg = String(rawMessage).trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setLoading(true);

    try {
      const resp = await axios.post(`${API_BASE}/chat`, {
        userId,
        message: userMsg,
        mode: mode,
        activeAddress: mode === 'non-custodial' ? mmAddress : null
      }, { headers: authHeaders });

      if (resp.data.thought) {
        setMessages(prev => [...prev, { role: 'ai', content: `*Thinking: ${resp.data.thought}*` }]);
      }
      setMessages(prev => [...prev, { role: 'ai', content: resp.data.message }]);

      const passwordWasUpdated = !!resp.data.passwordUpdated;
      if (passwordWasUpdated) {
        const newSecret = extractResetSecret(userMsg);
        if (newSecret) {
          setPassword(newSecret);
        }
      }

      if (resp.data.action === 'sign_required') {
        await signAndSend(resp.data.transactions);
      }

      const hasExecutedTransactions = Array.isArray(resp.data.details) && resp.data.details.length > 0;

      // Refresh dashboard only after transaction execution (custodial).
      if (!passwordWasUpdated && hasExecutedTransactions) {
        refreshDashboard();
      }
    } catch (err) {
      const serverMsg = err.response?.data?.message;
      if (err.response?.status === 401) {
        clearAuthAndReturnToLogin('Session expired. Please log in again.');
        return;
      }
      const fallback = err.response?.status === 401
        ? "Authentication error. Try logging in again."
        : "Request failed. Please try again.";
      setMessages(prev => [...prev, { role: 'ai', content: serverMsg || fallback }]);
    } finally {
      setLoading(false);
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    await submitUserMessage(input);
  };

  const startWhisperSpeechToText = async () => {
    try {
      speechDraftRef.current = '';
      setInput('');
      if (!voiceEngineRef.current) {
        const { IntentVoiceEngine } = await import('./lib/intent-voice');
        voiceEngineRef.current = new IntentVoiceEngine();
      }
      await voiceEngineRef.current.start();
      setIsListening(true);
      setMessages(prev => [...prev, { role: 'ai', content: 'Listening... click mic again to stop and transcribe.' }]);
    } catch (err) {
      setIsListening(false);
      setMessages(prev => [...prev, { role: 'ai', content: `Could not start microphone: ${err.message}` }]);
    }
  };

  const startSpeechToText = () => {
    if (!canUseNativeSpeechToText && !canUseWhisperSpeechToText) {
      setMessages(prev => [...prev, { role: 'ai', content: 'Speech-to-text is not supported in this browser.' }]);
      return;
    }
    if (isListening) return;

    if (!canUseNativeSpeechToText && canUseWhisperSpeechToText) {
      startWhisperSpeechToText();
      return;
    }

    const RecognitionClass = window.SpeechRecognition || window.webkitSpeechRecognition;
    const recognition = new RecognitionClass();
    speechRecognitionRef.current = recognition;
    recognition.lang = 'en-US';
    recognition.interimResults = true;
    recognition.maxAlternatives = 1;
    recognition.continuous = false;

    let finalTranscript = '';
    speechDraftRef.current = '';

    recognition.onresult = (event) => {
      let interim = '';
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const text = event.results[i][0]?.transcript || '';
        if (event.results[i].isFinal) {
          finalTranscript += text;
        } else {
          interim += text;
        }
      }
      const transcript = (finalTranscript + interim).trim();
      speechDraftRef.current = transcript;
      setInput(transcript);
    };

    recognition.onerror = () => {
      setMessages(prev => [...prev, { role: 'ai', content: 'Microphone input failed. Check browser mic permission and try again.' }]);
      setIsListening(false);
    };

    recognition.onend = async () => {
      setIsListening(false);
      const spoken = (finalTranscript || speechDraftRef.current || '').trim();
      if (spoken) {
        speechDraftRef.current = '';
        setInput('');
        await submitUserMessage(spoken);
      } else {
        setMessages(prev => [...prev, { role: 'ai', content: "I couldn't catch that voice input. Please try again." }]);
      }
    };

    try {
      setIsListening(true);
      setMessages(prev => [...prev, { role: 'ai', content: 'Listening... speak your command now.' }]);
      recognition.start();
    } catch (err) {
      setIsListening(false);
      setMessages(prev => [...prev, { role: 'ai', content: `Could not start microphone: ${err.message}` }]);
    }
  };

  const stopSpeechToText = () => {
    const pendingTranscript = (speechDraftRef.current || input || '').trim();

    if (voiceEngineRef.current && !canUseNativeSpeechToText) {
      setIsListening(false);
      setMessages(prev => [...prev, { role: 'ai', content: 'Transcribing voice input...' }]);
      voiceEngineRef.current.stopAndTranscribe()
        .then((text) => {
          if (text) {
            setInput(text);
            setMessages(prev => [...prev, { role: 'ai', content: 'Voice captured. Review the text in the input box and press Send.' }]);
          } else {
            setMessages(prev => [...prev, { role: 'ai', content: "I couldn't catch that voice input. Please try again." }]);
          }
        })
        .catch((err) => {
          setMessages(prev => [...prev, { role: 'ai', content: `Transcription failed: ${err.message}` }]);
        });
      return;
    }

    if (speechRecognitionRef.current) {
      try {
        speechRecognitionRef.current.stop();
      } catch {
        // no-op; recognizer may already be stopped
      }
    }

    setIsListening(false);
    if (pendingTranscript) {
      speechDraftRef.current = '';
      setInput('');
      submitUserMessage(pendingTranscript);
    } else {
      setMessages(prev => [...prev, { role: 'ai', content: "I couldn't catch that voice input. Please try again." }]);
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
          } catch {
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

  const handleSepoliaBadgeClick = async () => {
    if (!window.ethereum) {
      setMessages(prev => [...prev, { role: 'ai', content: 'MetaMask is not installed. Sepolia switch is only available via MetaMask.' }]);
      return;
    }

    try {
      const currentChainId = await window.ethereum.request({ method: 'eth_chainId' });
      if (currentChainId === SEPOLIA_CHAIN_ID) {
        setMessages(prev => [...prev, { role: 'ai', content: 'You are already on Sepolia Testnet.' }]);
        return;
      }

      try {
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: SEPOLIA_CHAIN_ID }],
        });
      } catch (switchError) {
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

      setMessages(prev => [...prev, { role: 'ai', content: 'Switched wallet network to Sepolia Testnet.' }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'ai', content: `Network switch failed: ${err.message}` }]);
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
      refreshDashboard();
    }
  };

  if (!isLoggedIn) {
    return (
      <div className="auth-container">
        <div
          className="glass-card"
          style={{ width: '400px' }}
        >
          <div style={{ textAlign: 'center', marginBottom: '32px' }}>
            <div className="btn" style={{ width: '64px', height: '64px', margin: '0 auto 16px', borderRadius: '20px' }}>
              <Lock size={32} />
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: '800' }}>IntentPay</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>Secure Wallet Access</p>
          </div>

          <form onSubmit={handleAuth}>
            <label htmlFor="auth-username" style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '600' }}>Username</label>
            <input
              id="auth-username"
              type="text"
              className="input-field"
              placeholder="Username"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              required
            />
            <label htmlFor="auth-password" style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '600' }}>Password</label>
            <input
              id="auth-password"
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
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="dashboard-title">
          <div className="brand-chip">IntentPay</div>
          <h2 style={{ fontSize: '14px', color: 'var(--text-muted)' }}>Secure Wallet of</h2>
          <h1 style={{ fontSize: '20px', fontWeight: '700' }}>{userId}</h1>
        </div>
        <div className="dashboard-actions">
          <button 
            onClick={connectMetaMask} 
            className={`btn header-action connect-btn ${mmAddress ? 'connected' : ''}`}
          >
            <Wallet size={16} />
            {mmAddress ? `${mmAddress.substring(0, 6)}...` : 'Connect MetaMask'}
          </button>
          <button onClick={handleLogout} className="btn header-action logout-btn">
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <div className="mode-switch">
        <button 
          onClick={() => setMode('custodial')}
          className={`btn mode-btn custodial ${mode === 'custodial' ? 'active' : ''}`}
        >
          <ShieldCheck size={14} style={{ marginRight: '8px' }} />
          Custodial (Server)
        </button>
        <button 
          onClick={() => setMode('non-custodial')}
          className={`btn mode-btn non-custodial ${mode === 'non-custodial' ? 'active' : ''}`}
        >
          <ShieldAlert size={14} style={{ marginRight: '8px' }} />
          Non-Custodial (MetaMask)
        </button>
      </div>

      <div
        className="balance-card floating"
      >
        <div className="balance-top-row">
          <div className={`security-pill ${securityStatus.score > 80 ? 'secure' : 'warning'}`}>
            <ShieldCheck size={16} color={securityStatus.score > 80 ? '#4ade80' : '#fbbf24'} />
            <span>
              Security: {securityStatus.status} ({securityStatus.score}%)
            </span>
          </div>
          <button
            onClick={handleSepoliaBadgeClick}
            className="btn network-chip"
            title="Switch connected wallet to Sepolia"
          >
            Sepolia Testnet
          </button>
        </div>
        <div className="balance-row">
          <span style={{ fontSize: '14px', opacity: 0.8 }}>Total Balance</span>
          <button
            onClick={() => refreshDashboard(true)}
            className="btn refresh-btn"
            disabled={isRefreshing}
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
          <button
            type="button"
            className="address-badge"
            onClick={copyToClipboard}
            aria-label="Copy wallet address"
          >
            <span>{wallet.address.substring(0, 10)}...{wallet.address.substring(34)}</span>
            {copied ? <CheckCircle2 size={14} color="#4ade80" /> : <Copy size={14} />}
          </button>
        )}
        <div className="refresh-meta">
          {lastRefreshAt ? `Last updated: ${lastRefreshAt.toLocaleTimeString()}` : 'Not refreshed yet'}
        </div>
        {refreshError && (
          <div className="refresh-error">
            {refreshError}
          </div>
        )}
      </div>

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

      <div className="glass-card history-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <History size={18} color="var(--primary)" />
          <h3 style={{ fontSize: '16px' }}>Transaction History</h3>
        </div>
        <div className="history-list">
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
              <h4 style={{ fontSize: '14px' }}>IntentPay Assistant</h4>
              <span style={{ fontSize: '10px', color: '#4ade80' }}>Secured Path</span>
            </div>
            <button
              type="button"
              onClick={() => setVoiceEnabled((v) => !v)}
              className="btn"
              style={{
                marginLeft: 'auto',
                padding: '6px',
                borderRadius: '8px',
                background: voiceEnabled ? 'rgba(74, 222, 128, 0.2)' : 'var(--glass)'
              }}
              title={canUseSpeech ? (voiceEnabled ? 'Disable voice playback' : 'Enable voice playback') : 'Speech synthesis not supported'}
              disabled={!canUseSpeech}
            >
              {voiceEnabled ? <Volume2 size={14} /> : <VolumeX size={14} />}
            </button>
            <button
              type="button"
              onClick={clearChatHistory}
              className="btn chat-clear-btn"
              title="Clear chat history"
            >
              Clear
            </button>
          </div>

          {!voiceHintDismissed && (
            <div className="voice-hint">
              Voice input: click mic, speak, then click mic again to transcribe.
              <button type="button" className="voice-hint-close" onClick={() => setVoiceHintDismissed(true)}>
                x
              </button>
            </div>
          )}

          <div className="chat-messages" role="log" aria-live="polite" aria-relevant="additions text">
            {messages.map((m, i) => (
              <div key={i} className={`message ${m.role}`}>
                {m.content}
              </div>
            ))}
            {loading && <div className="message ai">...</div>}
            <div ref={chatEndRef} />
          </div>

          <form onSubmit={sendMessage} className="chat-input-area">
            <button
              type="button"
              onClick={isListening ? stopSpeechToText : startSpeechToText}
              className="btn"
              style={{
                padding: '10px',
                background: isListening ? 'rgba(239, 68, 68, 0.25)' : 'var(--glass)'
              }}
              title={canUseSpeechToText ? (isListening ? 'Stop voice input' : 'Start voice input') : 'Speech-to-text not supported'}
              >
              {isListening ? <MicOff size={18} /> : <Mic size={18} />}
            </button>
            <input
              type="text"
              className="input-field"
              style={{ marginBottom: 0 }}
              placeholder={isListening ? "Listening..." : "Ask AI to send ETH..."}
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
