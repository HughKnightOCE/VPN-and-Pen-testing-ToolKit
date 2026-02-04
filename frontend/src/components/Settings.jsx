import React, { useState, useEffect } from 'react'
import axios from 'axios'
import './Settings.css'

function Settings() {
  const [settings, setSettings] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      const response = await axios.get('/api/settings')
      setSettings(response.data)
    } catch (err) {
      setError('Failed to fetch settings')
    }
  }

  return (
    <div className="settings">
      <h2>Settings & Configuration</h2>

      <div className="settings-grid">
        <div className="settings-section">
          <h3>🔒 Security Settings</h3>
          <div className="setting-item">
            <label>Encryption Algorithm</label>
            <div className="setting-value">AES-256-CBC</div>
            <p className="setting-desc">Military-grade encryption for all traffic</p>
          </div>
          <div className="setting-item">
            <label>Key Derivation</label>
            <div className="setting-value">PBKDF2 (100,000 iterations)</div>
            <p className="setting-desc">Strong password-based key derivation</p>
          </div>
        </div>

        <div className="settings-section">
          <h3>🌐 Network Settings</h3>
          <div className="setting-item">
            <label>Proxy Address</label>
            <div className="setting-value">127.0.0.1</div>
          </div>
          <div className="setting-item">
            <label>Proxy Port</label>
            <div className="setting-value">{settings?.proxy_port || 9050}</div>
          </div>
          <div className="setting-item">
            <label>Proxy Protocol</label>
            <div className="setting-value">SOCKS5</div>
          </div>
        </div>

        <div className="settings-section">
          <h3>🔍 DNS Settings</h3>
          <div className="setting-item">
            <label>DNS Protection</label>
            <div className="setting-value">
              {settings?.dns_protection ? '✅ Enabled' : '❌ Disabled'}
            </div>
          </div>
          <div className="setting-item">
            <label>DNS Servers</label>
            <div className="setting-list">
              <div>1.1.1.1 (Cloudflare)</div>
              <div>1.0.0.1 (Cloudflare)</div>
              <div>8.8.8.8 (Google)</div>
              <div>8.8.4.4 (Google)</div>
            </div>
          </div>
        </div>

        <div className="settings-section">
          <h3>🛡️ Kill Switch</h3>
          <div className="setting-item">
            <label>Status</label>
            <div className="setting-value">
              {settings?.kill_switch ? '✅ Enabled' : '❌ Disabled'}
            </div>
          </div>
          <p className="setting-desc">
            When enabled, all internet traffic is blocked if VPN connection drops
          </p>
        </div>
      </div>

      <div className="system-info">
        <h3>System Information</h3>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">Backend Status:</span>
            <span className="info-value">✅ Running</span>
          </div>
          <div className="info-item">
            <span className="info-label">Frontend Version:</span>
            <span className="info-value">1.0.0</span>
          </div>
          <div className="info-item">
            <span className="info-label">Python Version:</span>
            <span className="info-value">3.9+</span>
          </div>
          <div className="info-item">
            <span className="info-label">Environment:</span>
            <span className="info-value">Production</span>
          </div>
        </div>
      </div>

      <div className="info-box">
        <h3>⚠️ Important Information</h3>
        <ul>
          <li>This tool is for authorized security testing only</li>
          <li>Unauthorized access to computer systems is illegal</li>
          <li>Always obtain proper authorization before testing</li>
          <li>Keep your encryption password secure and unique</li>
          <li>Monitor your traffic regularly for suspicious activity</li>
          <li>Update dependencies regularly for security patches</li>
        </ul>
      </div>

      <div className="documentation">
        <h3>📚 Documentation</h3>
        <div className="doc-links">
          <a href="#" className="doc-link">User Guide</a>
          <a href="#" className="doc-link">API Documentation</a>
          <a href="#" className="doc-link">Security Best Practices</a>
          <a href="#" className="doc-link">Troubleshooting</a>
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}
    </div>
  )
}

export default Settings
