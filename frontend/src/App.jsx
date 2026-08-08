import { useEffect, useState } from "react";
import Login from "./Login";

const API_BASE = "http://192.168.56.101:8000";

function App() {
  const [token, setToken] = useState(null);
  const [status, setStatus] = useState("checking...");
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);
  const [loadingId, setLoadingId] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  const [activeTab, setActiveTab] = useState("vulnerabilities");
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  const [networkHosts, setNetworkHosts] = useState([]);
  const [networkAlerts, setNetworkAlerts] = useState([]);
  const [scans, setScans] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditError, setAuditError] = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then((res) => res.json())
      .then((data) => setStatus(data.status))
      .catch(() => setStatus("could not reach backend"));
  }, []);

  const fetchVulnerabilities = () => {
    if (!token) return;

    const params = new URLSearchParams();
    if (severityFilter) params.append("severity", severityFilter);
    if (searchTerm) params.append("search", searchTerm);

    fetch(`${API_BASE}/vulnerabilities?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => setVulnerabilities(Array.isArray(data) ? data : []))
      .catch(() => setVulnerabilities([]));
  };

  useEffect(() => {
    fetchVulnerabilities();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, severityFilter]);

  const fetchNetwork = () => {
    if (!token) return;
    fetch(`${API_BASE}/network/hosts`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.json())
      .then((data) => setNetworkHosts(Array.isArray(data) ? data : []))
      .catch(() => setNetworkHosts([]));

    fetch(`${API_BASE}/network/alerts`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.json())
      .then((data) => setNetworkAlerts(Array.isArray(data) ? data : []))
      .catch(() => setNetworkAlerts([]));
  };

  const fetchScans = () => {
    if (!token) return;
    fetch(`${API_BASE}/scans`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.json())
      .then((data) => setScans(Array.isArray(data) ? data : []))
      .catch(() => setScans([]));
  };

  const fetchAuditLogs = () => {
    if (!token) return;
    setAuditError("");
    fetch(`${API_BASE}/audit-logs`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) {
          setAuditLogs(data);
        } else {
          setAuditError(data.detail || "Could not load audit logs");
        }
      })
      .catch(() => setAuditError("Could not reach backend"));
  };

  useEffect(() => {
    if (activeTab === "network") fetchNetwork();
    if (activeTab === "reports") fetchScans();
    if (activeTab === "audit") fetchAuditLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, token]);

  const viewAiReport = (vulnId) => {
    setLoadingId(vulnId);
    fetch(`${API_BASE}/vulnerabilities/${vulnId}/ai-report`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => {
        setSelectedReport({ vulnId, ...data });
        setLoadingId(null);
      })
      .catch(() => {
        setSelectedReport({ vulnId, detail: "Could not load AI report" });
        setLoadingId(null);
      });
  };

  const askAssistant = () => {
    if (!chatInput.trim()) return;

    const question = chatInput;
    setChatMessages((prev) => [...prev, { role: "user", text: question }]);
    setChatInput("");
    setChatLoading(true);

    fetch(`${API_BASE}/ai-assistant/ask?question=${encodeURIComponent(question)}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => {
        setChatMessages((prev) => [...prev, { role: "assistant", text: data.answer }]);
        setChatLoading(false);
      })
      .catch(() => {
        setChatMessages((prev) => [...prev, { role: "assistant", text: "Error reaching AI assistant." }]);
        setChatLoading(false);
      });
  };

  const downloadCsv = () => {
    fetch(`${API_BASE}/reports/vulnerabilities/csv`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.blob())
      .then((blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "vulnerabilities_report.csv";
        a.click();
        window.URL.revokeObjectURL(url);
      });
  };

  const severityClass = (sev) => {
    switch (sev) {
      case "critical": return { background: "rgba(244,63,94,0.15)", color: "var(--critical)" };
      case "high": return { background: "rgba(251,146,60,0.15)", color: "var(--high)" };
      case "medium": return { background: "rgba(251,191,36,0.15)", color: "var(--medium)" };
      case "low": return { background: "rgba(74,222,128,0.15)", color: "var(--low)" };
      default: return { background: "rgba(139,147,168,0.15)", color: "var(--text-dim)" };
    }
  };

  const counts = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter((v) => v.severity === "critical").length,
    high: vulnerabilities.filter((v) => v.severity === "high").length,
    medium: vulnerabilities.filter((v) => v.severity === "medium").length,
  };

  const tabTitles = {
    vulnerabilities: "Vulnerabilities",
    assistant: "AI Assistant",
    network: "Network & IDS",
    reports: "Reports",
    audit: "Audit Log",
  };

  if (!token) {
    return <Login onLoginSuccess={(newToken) => setToken(newToken)} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">S</div>
          <div className="brand-text">
            <span className="brand-title">SentinelAI</span>
            <span className="brand-sub">SOC Dashboard</span>
          </div>
        </div>

        <nav className="nav">
          <button
            className={`nav-item ${activeTab === "vulnerabilities" ? "active" : ""}`}
            onClick={() => setActiveTab("vulnerabilities")}
          >
            Vulnerabilities
          </button>
          <button
            className={`nav-item ${activeTab === "network" ? "active" : ""}`}
            onClick={() => setActiveTab("network")}
          >
            Network & IDS
          </button>
          <button
            className={`nav-item ${activeTab === "reports" ? "active" : ""}`}
            onClick={() => setActiveTab("reports")}
          >
            Reports
          </button>
          <button
            className={`nav-item ${activeTab === "assistant" ? "active" : ""}`}
            onClick={() => setActiveTab("assistant")}
          >
            AI Assistant
          </button>
          <button
            className={`nav-item ${activeTab === "audit" ? "active" : ""}`}
            onClick={() => setActiveTab("audit")}
          >
            Audit Log
          </button>
        </nav>

        <div className="sidebar-footer">
          <button className="logout-btn" onClick={() => setToken(null)}>
            Log Out
          </button>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <h1 className="page-title">{tabTitles[activeTab]}</h1>
          <div className="status-pill">
            <span className={`status-dot ${status !== "ok" ? "down" : ""}`}></span>
            {status === "ok" ? "SYSTEM NOMINAL" : "BACKEND UNREACHABLE"}
          </div>
        </div>

        {activeTab === "vulnerabilities" && (
          <>
            <div className="stats-row">
              <div className="stat-card">
                <div className="stat-label">Total Findings</div>
                <div className="stat-value">{counts.total}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Critical</div>
                <div className="stat-value" style={{ color: "var(--critical)" }}>{counts.critical}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">High</div>
                <div className="stat-value" style={{ color: "var(--high)" }}>{counts.high}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Medium</div>
                <div className="stat-value" style={{ color: "var(--medium)" }}>{counts.medium}</div>
              </div>
            </div>

            <div className="controls-row">
              <select className="select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

              <input
                type="text"
                className="text-input"
                placeholder="Search by title..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && fetchVulnerabilities()}
              />

              <button className="btn btn-primary" onClick={fetchVulnerabilities}>Search</button>
              <button className="btn btn-secondary" onClick={downloadCsv}>Export CSV</button>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Analysis</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerabilities.map((v) => (
                    <tr key={v.id}>
                      <td><span className="severity-badge" style={severityClass(v.severity)}>{v.severity}</span></td>
                      <td>{v.title}</td>
                      <td className="mono">{v.file_path}</td>
                      <td className="mono">{v.line_number}</td>
                      <td>
                        <button className="view-btn" onClick={() => viewAiReport(v.id)}>
                          {loadingId === v.id ? "Loading..." : "View"}
                        </button>
                      </td>
                    </tr>
                  ))}
                  {vulnerabilities.length === 0 && (
                    <tr><td colSpan="5" style={{ textAlign: "center", color: "var(--text-faint)", padding: "24px" }}>No findings match the current filters.</td></tr>
                  )}
                </tbody>
              </table>
            </div>

            {selectedReport && (
              <div className="report-panel">
                <h3>AI Analysis — Finding #{selectedReport.vulnId}</h3>
                {selectedReport.detail ? (
                  <p style={{ color: "var(--text-dim)" }}>{selectedReport.detail}</p>
                ) : (
                  <>
                    <p style={{ color: "var(--text-dim)" }}>Risk Score: <span className="risk-score">{selectedReport.risk_score}/10</span></p>
                    <p><strong>Summary:</strong> {selectedReport.summary}</p>
                    <p><strong>Remediation:</strong> {selectedReport.remediation}</p>
                  </>
                )}
                <button className="btn btn-secondary" onClick={() => setSelectedReport(null)}>Close</button>
              </div>
            )}
          </>
        )}

        {activeTab === "network" && (
          <>
            <h3 style={{ fontSize: "14px", color: "var(--text-dim)", marginBottom: "10px" }}>Discovered Hosts</h3>
            <div className="table-wrap" style={{ marginBottom: "28px" }}>
              <table>
                <thead>
                  <tr><th>IP Address</th><th>Hostname</th><th>Open Ports</th><th>Last Seen</th></tr>
                </thead>
                <tbody>
                  {networkHosts.map((h) => (
                    <tr key={h.id}>
                      <td className="mono">{h.ip_address}</td>
                      <td>{h.hostname || "—"}</td>
                      <td className="mono">{h.open_ports || "—"}</td>
                      <td className="mono">{h.last_seen}</td>
                    </tr>
                  ))}
                  {networkHosts.length === 0 && (
                    <tr><td colSpan="4" style={{ textAlign: "center", color: "var(--text-faint)", padding: "20px" }}>No hosts discovered yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>

            <h3 style={{ fontSize: "14px", color: "var(--text-dim)", marginBottom: "10px" }}>Snort Alerts</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Severity</th><th>Source</th><th>Destination</th><th>Message</th><th>Time</th></tr>
                </thead>
                <tbody>
                  {networkAlerts.map((a) => (
                    <tr key={a.id}>
                      <td><span className="severity-badge" style={severityClass(a.severity)}>{a.severity}</span></td>
                      <td className="mono">{a.source_ip}</td>
                      <td className="mono">{a.dest_ip}</td>
                      <td>{a.alert_message}</td>
                      <td className="mono">{a.created_at}</td>
                    </tr>
                  ))}
                  {networkAlerts.length === 0 && (
                    <tr><td colSpan="5" style={{ textAlign: "center", color: "var(--text-faint)", padding: "20px" }}>No alerts recorded yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === "reports" && (
          <>
            <div className="controls-row">
              <button className="btn btn-primary" onClick={downloadCsv}>Export Vulnerabilities CSV</button>
            </div>

            <h3 style={{ fontSize: "14px", color: "var(--text-dim)", marginBottom: "10px" }}>Scan History</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Scanner</th><th>Status</th><th>Started At</th></tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id}>
                      <td>{s.scanner_type}</td>
                      <td>{s.status}</td>
                      <td className="mono">{s.started_at}</td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr><td colSpan="3" style={{ textAlign: "center", color: "var(--text-faint)", padding: "20px" }}>No scans recorded yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === "audit" && (
          <div className="table-wrap">
            {auditError ? (
              <p style={{ padding: "20px", color: "var(--critical)" }}>{auditError}</p>
            ) : (
              <table>
                <thead>
                  <tr><th>User ID</th><th>Action</th><th>Details</th><th>Timestamp</th></tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id}>
                      <td className="mono">{log.user_id}</td>
                      <td>{log.action}</td>
                      <td>{log.details}</td>
                      <td className="mono">{log.timestamp}</td>
                    </tr>
                  ))}
                  {auditLogs.length === 0 && (
                    <tr><td colSpan="4" style={{ textAlign: "center", color: "var(--text-faint)", padding: "20px" }}>No audit entries yet.</td></tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === "assistant" && (
          <div style={{ maxWidth: "700px" }}>
            <p style={{ color: "var(--text-faint)", marginTop: "-8px", marginBottom: "18px" }}>
              Ask a security question — e.g. "What is SQL Injection?"
            </p>

            <div className="chat-window">
              {chatMessages.length === 0 && (
                <p style={{ color: "var(--text-faint)" }}>No messages yet — ask something below.</p>
              )}
              {chatMessages.map((msg, i) => (
                <div key={i} className={`chat-msg ${msg.role}`}>
                  <span className={`chat-bubble ${msg.role}`}>{msg.text}</span>
                </div>
              ))}
              {chatLoading && <p style={{ color: "var(--text-faint)" }}>Thinking...</p>}
            </div>

            <div className="chat-input-row">
              <input
                type="text"
                className="text-input"
                style={{ flexGrow: 1 }}
                placeholder="Ask a security question..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && askAssistant()}
              />
              <button className="btn btn-primary" onClick={askAssistant} disabled={chatLoading}>Ask</button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
