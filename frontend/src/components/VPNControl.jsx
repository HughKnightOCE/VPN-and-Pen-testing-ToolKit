import React, { useState, useEffect } from 'react'
import axios from 'axios'
import './VPNControl.css'

function VPNControl() {
  const [vpnActive, setVpnActive] = useState(false)
  const [killSwitch, setKillSwitch] = useState(false)
  const [dnsLeakTest, setDnsLeakTest] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const toggleVPN = async () => {
    setLoading(true)
    setError(null)
    try {
      if (vpnActive) {
        await axios.post('/api/vpn/stop')
        setVpnActive(false)
      } else {
        await axios.post('/api/vpn/start')
        setVpnActive(true)
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to toggle VPN')
    }
    setLoading(false)
  }

  const toggleKillSwitch = async () => {
    try {
      await axios.post('/api/vpn/kill-switch', { enable: !killSwitch })
      setKillSwitch(!killSwitch)
    } catch (err) {
      setError('Failed to toggle kill switch')
    }
  }

  const testDNSLeak = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/vpn/dns-leak-test')
      setDnsLeakTest(response.data)
    } catch (err) {
      setError('Failed to test DNS leak')
    }
    setLoading(false)
  }

  return (
    <div className="vpn-control">
      <h2>VPN Proxy Control</h2>
      
      <div className="control-panel">
        <div className="vpn-toggle">
          <div className={`toggle-switch ${vpnActive ? 'active' : ''}`}>
            <button 
              className="toggle-btn" 
              onClick={toggleVPN}
              disabled={loading}
            >
              {vpnActive ? 'VPN ON' : 'VPN OFF'}
            </button>
          </div>
          <p className="status-text">
            {vpnActive ? '🟢 VPN is Active' : '🔴 VPN is Inactive'}
          </p>
        </div>

        <div className="features-grid">
          <div className="feature-card">
            <h3>🔒 Encryption</h3>
            <p>AES-256 traffic encryption</p>
            <span className="status-badge active">ACTIVE</span>
          </div>

          <div className="feature-card">
            <h3>🛡️ DNS Protection</h3>
            <p>Prevents DNS leaks</p>
            <button onClick={testDNSLeak} disabled={loading} className="test-btn">
              Test DNS
            </button>
          </div>

          <div className="feature-card">
            <h3>🚫 Kill Switch</h3>
            <p>Disable internet if VPN drops</p>
            <button 
              onClick={toggleKillSwitch}
              className={`toggle-small ${killSwitch ? 'active' : ''}`}
            >
              {killSwitch ? 'ON' : 'OFF'}
            </button>
          </div>

          <div className="feature-card">
            <h3>🔗 Proxy</h3>
            <p>SOCKS5 @ 127.0.0.1:9050</p>
            <span className="status-badge">READY</span>
          </div>
        </div>

        {dnsLeakTest && (
          <div className={`dns-result ${dnsLeakTest.leak_detected ? 'leak' : 'safe'}`}>
            <h4>DNS Leak Test Result</h4>
            <p>{dnsLeakTest.leak_detected ? '⚠️ Leak Detected' : '✅ Protected'}</p>
            {dnsLeakTest.leaked_ips?.length > 0 && (
              <div className="leaked-ips">
                <strong>Leaked IPs:</strong>
                <ul>
                  {dnsLeakTest.leaked_ips.map((ip, i) => (
                    <li key={i}>{ip}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {error && <div className="error-message">{error}</div>}
      </div>

      <div className="info-section">
        <h3>Setup Instructions</h3>
        <div className="instructions">
          <p><strong>To use this VPN proxy:</strong></p>
          <ol>
            <li>Click "VPN ON" to start the proxy server</li>
            <li>Configure your application with SOCKS5 proxy: 127.0.0.1:9050</li>
            <li>All traffic will be encrypted with AES-256</li>
            <li>DNS queries use secure servers (Cloudflare/Google)</li>
            <li>Enable Kill Switch to block all traffic if connection drops</li>
          </ol>
        </div>
      </div>
    </div>
  )
}

export default VPNControl
