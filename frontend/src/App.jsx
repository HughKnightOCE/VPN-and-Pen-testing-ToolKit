import React, { useState, useEffect } from 'react'
import axios from 'axios'
import VPNControl from './components/VPNControl'
import TrafficMonitor from './components/TrafficMonitor'
import PentestTools from './components/PentestTools'
import ThreatPanel from './components/ThreatPanel'
import Settings from './components/Settings'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('vpn')
  const [vpnStatus, setVpnStatus] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check backend health
    axios.get('/api/health')
      .then(() => setLoading(false))
      .catch(() => setLoading(false))
  }, [])

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-content">
          <h1>🛡️ VPN Proxy + Pentesting Toolkit</h1>
          <p>Professional Security Testing Platform</p>
        </div>
      </header>

      <nav className="app-nav">
        <button 
          className={`nav-btn ${activeTab === 'vpn' ? 'active' : ''}`}
          onClick={() => setActiveTab('vpn')}
        >
          VPN Control
        </button>
        <button 
          className={`nav-btn ${activeTab === 'traffic' ? 'active' : ''}`}
          onClick={() => setActiveTab('traffic')}
        >
          Traffic Monitor
        </button>
        <button 
          className={`nav-btn ${activeTab === 'threats' ? 'active' : ''}`}
          onClick={() => setActiveTab('threats')}
        >
          🛡️ Threats
        </button>
        <button 
          className={`nav-btn ${activeTab === 'pentest' ? 'active' : ''}`}
          onClick={() => setActiveTab('pentest')}
        >
          Pentesting Tools
        </button>
        <button 
          className={`nav-btn ${activeTab === 'settings' ? 'active' : ''}`}
          onClick={() => setActiveTab('settings')}
        >
          Settings
        </button>
      </nav>

      <main className="app-main">
        {loading ? (
          <div className="loading">
            <div className="spinner"></div>
            <p>Connecting to backend...</p>
          </div>
        ) : (
          <>
            {activeTab === 'vpn' && <VPNControl />}
            {activeTab === 'traffic' && <TrafficMonitor />}
            {activeTab === 'threats' && <ThreatPanel />}
            {activeTab === 'pentest' && <PentestTools />}
            {activeTab === 'settings' && <Settings />}
          </>
        )}
      </main>

      <footer className="app-footer">
        <p>VPN Proxy + Pentesting Toolkit • For Authorized Security Testing Only</p>
      </footer>
    </div>
  )
}

export default App
