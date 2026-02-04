import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import './TrafficMonitor.css'

function TrafficMonitor() {
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    const interval = setInterval(() => {
      fetchStats()
      fetchHistory()
    }, 2000)

    fetchStats()
    fetchHistory()

    return () => clearInterval(interval)
  }, [])

  const fetchStats = async () => {
    try {
      const response = await axios.get('/api/traffic/stats')
      setStats(response.data)
    } catch (err) {
      setError('Failed to fetch traffic stats')
    }
  }

  const fetchHistory = async () => {
    try {
      const response = await axios.get('/api/traffic/history?limit=50')
      setHistory(response.data.history)
    } catch (err) {
      console.error('Failed to fetch history')
    }
  }

  const clearHistory = async () => {
    try {
      await axios.post('/api/traffic/clear')
      setHistory([])
      setStats(null)
    } catch (err) {
      setError('Failed to clear history')
    }
  }

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const chartData = history.map((entry, i) => ({
    time: i,
    bytes: entry.bytes || 0,
    cumulative: history.slice(0, i + 1).reduce((sum, e) => sum + (e.bytes || 0), 0)
  }))

  return (
    <div className="traffic-monitor">
      <h2>Traffic Monitor</h2>

      {stats && (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-icon">📤</div>
              <div className="stat-content">
                <p className="stat-label">Bytes Sent</p>
                <p className="stat-value">{formatBytes(stats.bytes_sent)}</p>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">📥</div>
              <div className="stat-content">
                <p className="stat-label">Bytes Received</p>
                <p className="stat-value">{formatBytes(stats.bytes_received)}</p>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">🔀</div>
              <div className="stat-content">
                <p className="stat-label">Total Data</p>
                <p className="stat-value">{formatBytes(stats.total_bytes)}</p>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">🌐</div>
              <div className="stat-content">
                <p className="stat-label">Connections</p>
                <p className="stat-value">{stats.active_connections}</p>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">📦</div>
              <div className="stat-content">
                <p className="stat-label">Total Packets</p>
                <p className="stat-value">{stats.total_packets}</p>
              </div>
            </div>
          </div>

          {chartData.length > 0 && (
            <div className="chart-container">
              <h3>Traffic History</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip 
                    formatter={(value) => formatBytes(value)}
                    labelFormatter={(label) => `Packet ${label}`}
                  />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="bytes" 
                    stroke="#0066ff" 
                    name="Bytes per Packet"
                    dot={false}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="cumulative" 
                    stroke="#2dce89" 
                    name="Cumulative Bytes"
                    strokeDasharray="5 5"
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {stats.connections && stats.connections.length > 0 && (
            <div className="connections-table">
              <h3>Active Connections</h3>
              <table>
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Total Bytes</th>
                    <th>Sent</th>
                    <th>Received</th>
                    <th>Packets</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.connections.map((conn, i) => (
                    <tr key={i}>
                      <td>{conn.host}</td>
                      <td>{conn.port}</td>
                      <td>{formatBytes(conn.total_bytes)}</td>
                      <td>{formatBytes(conn.send_bytes)}</td>
                      <td>{formatBytes(conn.receive_bytes)}</td>
                      <td>{conn.packet_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      <div className="monitor-actions">
        <button onClick={clearHistory} className="btn-danger">
          Clear History
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}
    </div>
  )
}

export default TrafficMonitor
