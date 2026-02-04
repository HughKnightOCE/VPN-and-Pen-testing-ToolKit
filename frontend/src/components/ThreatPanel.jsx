import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './ThreatPanel.css';

export default function ThreatPanel() {
  const [threatStatus, setThreatStatus] = useState({
    level: 'LOW',
    total_threats: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    blocked_ips: 0
  });
  const [threats, setThreats] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [autoBlock, setAutoBlock] = useState(false);
  const [loading, setLoading] = useState(true);

  // Fetch threat status every 2 seconds
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/threats/status');
        setThreatStatus(response.data);
        setLoading(false);
      } catch (error) {
        console.error('Error fetching threat status:', error);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  // Fetch threats on demand
  const fetchThreats = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/threats/alerts?limit=50');
      setThreats(response.data.threats || []);
    } catch (error) {
      console.error('Error fetching threats:', error);
    }
  };

  // Fetch blocked IPs
  const fetchBlockedIps = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/threats/blocked-ips');
      setBlockedIps(response.data.blocked_ips || []);
    } catch (error) {
      console.error('Error fetching blocked IPs:', error);
    }
  };

  useEffect(() => {
    fetchThreats();
    fetchBlockedIps();
  }, []);

  const handleBlockIp = async (ip) => {
    try {
      await axios.post('http://localhost:5000/api/threats/block', {
        ip,
        action: 'block',
        reason: 'Manual block'
      });
      fetchBlockedIps();
    } catch (error) {
      console.error('Error blocking IP:', error);
    }
  };

  const handleUnblockIp = async (ip) => {
    try {
      await axios.post('http://localhost:5000/api/threats/block', {
        ip,
        action: 'unblock'
      });
      fetchBlockedIps();
    } catch (error) {
      console.error('Error unblocking IP:', error);
    }
  };

  const getThreatLevelColor = (level) => {
    switch (level) {
      case 'CRITICAL': return '#ff0000';
      case 'HIGH': return '#ff6600';
      case 'MEDIUM': return '#ffaa00';
      case 'LOW': return '#00cc00';
      default: return '#666666';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return '#ff0000';
      case 'HIGH': return '#ff6600';
      case 'MEDIUM': return '#ffaa00';
      case 'LOW': return '#00cc00';
      default: return '#666666';
    }
  };

  return (
    <div className="threat-panel">
      <h2>🛡️ Threat Detection Dashboard</h2>

      {/* Threat Level Gauge */}
      <div className="threat-gauge-container">
        <div className="threat-gauge" style={{ borderColor: getThreatLevelColor(threatStatus.level) }}>
          <div className="gauge-level" style={{ color: getThreatLevelColor(threatStatus.level) }}>
            {threatStatus.level}
          </div>
          <div className="gauge-sublevel">
            Total Threats: {threatStatus.total_threats}
          </div>
        </div>

        {/* Threat Statistics */}
        <div className="threat-stats">
          <div className="stat critical">
            <span className="label">🔴 CRITICAL</span>
            <span className="value">{threatStatus.critical}</span>
          </div>
          <div className="stat high">
            <span className="label">🟠 HIGH</span>
            <span className="value">{threatStatus.high}</span>
          </div>
          <div className="stat medium">
            <span className="label">🟡 MEDIUM</span>
            <span className="value">{threatStatus.medium}</span>
          </div>
          <div className="stat low">
            <span className="label">🟢 LOW</span>
            <span className="value">{threatStatus.low}</span>
          </div>
        </div>
      </div>

      {/* Auto-Block Toggle */}
      <div className="auto-block-section">
        <label>
          <input
            type="checkbox"
            checked={autoBlock}
            onChange={(e) => setAutoBlock(e.target.checked)}
          />
          <span>Auto-block malicious IPs</span>
        </label>
        <p className="info-text">⚠️ When enabled, suspicious IPs are automatically blocked</p>
      </div>

      {/* Blocked IPs Section */}
      <div className="blocked-ips-section">
        <h3>🚫 Blocked IPs ({blockedIps.length})</h3>
        {blockedIps.length > 0 ? (
          <div className="blocked-ips-list">
            {blockedIps.map((ip, idx) => (
              <div key={idx} className="blocked-ip-item">
                <span className="ip">{ip}</span>
                <button
                  className="unblock-btn"
                  onClick={() => handleUnblockIp(ip)}
                >
                  Unblock
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="empty-state">No blocked IPs</p>
        )}
      </div>

      {/* Recent Threats */}
      <div className="threats-section">
        <h3>⚠️ Recent Threats ({threats.length})</h3>
        {threats.length > 0 ? (
          <div className="threats-list">
            {threats.map((threat, idx) => (
              <div
                key={idx}
                className="threat-item"
                style={{ borderLeftColor: getSeverityColor(threat.severity) }}
              >
                <div className="threat-header">
                  <span className="threat-type">{threat.threat_type.toUpperCase()}</span>
                  <span
                    className="severity"
                    style={{ backgroundColor: getSeverityColor(threat.severity) }}
                  >
                    {threat.severity}
                  </span>
                  <span className="time">
                    {new Date(threat.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <div className="threat-details">
                  <div className="detail-item">
                    <strong>Source:</strong> {threat.source_ip}
                  </div>
                  {threat.destination_ip && threat.destination_ip !== 'unknown' && (
                    <div className="detail-item">
                      <strong>Destination:</strong> {threat.destination_ip}
                    </div>
                  )}
                  <div className="detail-item">
                    <strong>Details:</strong>{' '}
                    {JSON.stringify(threat.details, null, 2)}
                  </div>
                </div>

                {!blockedIps.includes(threat.source_ip) && (
                  <button
                    className="block-btn"
                    onClick={() => handleBlockIp(threat.source_ip)}
                  >
                    Block IP
                  </button>
                )}
                {blockedIps.includes(threat.source_ip) && (
                  <span className="already-blocked">✓ Already Blocked</span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="empty-state">No threats detected ✓</p>
        )}
      </div>

      <button className="refresh-btn" onClick={() => { fetchThreats(); fetchBlockedIps(); }}>
        🔄 Refresh
      </button>
    </div>
  );
}
