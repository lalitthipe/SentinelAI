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
  const [dashboardData, setDashboardData] = useState(null);

  const [networkHosts, setNetworkHosts] = useState([]);
  const [snortAlerts, setSnortAlerts] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);

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

  const fetchDashboard = () => {
    if (!token) return;
    fetch(`${API_BASE}/dashboard/summary`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => setDashboardData(data))
      .catch(() => setDashboardData(null));
  };
  const fetchNetworkData = () => {
    if (!token) return;
    fetch(`${API_BASE}/network/hosts`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => setNetworkHosts(Array.isArray(data) ? data : []))
      .catch(() => setNetworkHosts([]));

    fetch(`${API_BASE}/network/alerts`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => setSnortAlerts(Array.isArray(data) ? data : []))
      .catch(() => setSnortAlerts([]));
  };
  const fetchScanHistory = () => {
    if (!token) return;
    fetch(`${API_BASE}/scans`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => setScanHistory(Array.isArray(data) ? data : []))
      .catch(() => setScanHistory([]));
  };

  const downloadPdfReport = () => {
    fetch(`${API_BASE}/reports/vulnerabilities/pdf`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.blob())
      .then((blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "vulnerabilities_report.pdf";
        a.click();
        window.URL.revokeObjectURL(url);
      });
  };
  useEffect(() => {
    fetchVulnerabilities();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, severityFilter]);
  useEffect(() => {
    if (activeTab === "dashboard") fetchDashboard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, token]);
  useEffect(() => {
    if (activeTab === "dashboard") fetchDashboard();
    if (activeTab === "network") fetchNetworkData();
    if (activeTab === "reports") fetchScanHistory();
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

  const severityColor = (sev) => {
    switch (sev) {
      case "critical": return "#ff4d4d";
      case "high": return "#ff944d";
      case "medium": return "#ffd24d";
      case "low": return "#8ac926";
      default: return "#ccc";
    }
  };

  if (!token) {
    return <Login onLoginSuccess={(newToken) => setToken(newToken)} />;
  }

  return (
    <div style={{ fontFamily: "sans-serif", padding: "2rem", color: "#eee", background: "#111", minHeight: "100vh" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1>SentinelAI</h1>
        <button
          onClick={() => setToken(null)}
          style={{
            background: "#333", color: "#eee", border: "1px solid #555",
            padding: "6px 14px", borderRadius: "4px", cursor: "pointer", height: "fit-content",
          }}
        >
          Log Out
        </button>
      </div>
      <p>Backend status: {status}</p>

      <div style={{ display: "flex", gap: "0.5rem", margin: "1rem 0" }}>
        <button
          onClick={() => setActiveTab("vulnerabilities")}
          style={{
            background: activeTab === "vulnerabilities" ? "#3b82f6" : "#333",
            color: "#fff", border: "none", padding: "8px 16px",
            borderRadius: "4px", cursor: "pointer",
          }}
        >
          Vulnerabilities
        </button>
        <button
          onClick={() => setActiveTab("assistant")}
          style={{
            background: activeTab === "assistant" ? "#3b82f6" : "#333",
            color: "#fff", border: "none", padding: "8px 16px",
            borderRadius: "4px", cursor: "pointer",
          }}
        >
          AI Assistant
        </button>
	<button
          onClick={() => setActiveTab("dashboard")}
          style={{
            background: activeTab === "dashboard" ? "#3b82f6" : "#333",
            color: "#fff", border: "none", padding: "8px 16px",
            borderRadius: "4px", cursor: "pointer",
          }}
        >
          Dashboard
        </button>
	<button
          onClick={() => setActiveTab("network")}
          style={{
            background: activeTab === "network" ? "#3b82f6" : "#333",
            color: "#fff", border: "none", padding: "8px 16px",
            borderRadius: "4px", cursor: "pointer",
          }}
        >
          Network
        </button>
	<button
          onClick={() => setActiveTab("reports")}
          style={{
            background: activeTab === "reports" ? "#3b82f6" : "#333",
            color: "#fff", border: "none", padding: "8px 16px",
            borderRadius: "4px", cursor: "pointer",
          }}
        >
          Reports
        </button>
      </div>
      {activeTab === "dashboard" && (
        <div>
          <h2>Dashboard</h2>
          {!dashboardData ? (
            <p>Loading...</p>
          ) : (
            <>
              <div style={{ display: "flex", gap: "1rem", marginBottom: "1.5rem", flexWrap: "wrap" }}>
                <div style={{ background: "#1a1a1a", border: "1px solid #444", borderRadius: "8px", padding: "1rem", minWidth: "160px" }}>
                  <p style={{ color: "#aaa", margin: 0 }}>Security Score</p>
                  <p style={{ fontSize: "2rem", fontWeight: "bold", margin: 0 }}>{dashboardData.security_score}</p>
                </div>
                <div style={{ background: "#1a1a1a", border: "1px solid #444", borderRadius: "8px", padding: "1rem", minWidth: "160px" }}>
                  <p style={{ color: "#aaa", margin: 0 }}>Total Vulnerabilities</p>
                  <p style={{ fontSize: "2rem", fontWeight: "bold", margin: 0 }}>{dashboardData.total_vulnerabilities}</p>
                </div>
                <div style={{ background: "#1a1a1a", border: "1px solid #444", borderRadius: "8px", padding: "1rem", minWidth: "160px" }}>
                  <p style={{ color: "#aaa", margin: 0 }}>Network Hosts</p>
                  <p style={{ fontSize: "2rem", fontWeight: "bold", margin: 0 }}>{dashboardData.total_hosts}</p>
                </div>
                <div style={{ background: "#1a1a1a", border: "1px solid #444", borderRadius: "8px", padding: "1rem", minWidth: "160px" }}>
                  <p style={{ color: "#aaa", margin: 0 }}>Snort Alerts</p>
                  <p style={{ fontSize: "2rem", fontWeight: "bold", margin: 0 }}>{dashboardData.total_alerts}</p>
                </div>
              </div>

              <h3>Severity Breakdown</h3>
              <div style={{ display: "flex", gap: "1rem", marginBottom: "1.5rem" }}>
                {Object.entries(dashboardData.severity_counts).map(([sev, count]) => (
                  <div key={sev} style={{
                    background: "#1a1a1a", border: "1px solid #444", borderRadius: "8px",
                    padding: "0.75rem 1.25rem", textAlign: "center",
                  }}>
                    <p style={{ color: severityColor(sev), fontWeight: "bold", margin: 0, textTransform: "capitalize" }}>{sev}</p>
                    <p style={{ fontSize: "1.5rem", margin: 0 }}>{count}</p>
                  </div>
                ))}
              </div>

              <h3>Recent Scans</h3>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ textAlign: "left", borderBottom: "1px solid #444" }}>
                    <th style={{ padding: "8px" }}>Scanner</th>
                    <th style={{ padding: "8px" }}>Status</th>
                    <th style={{ padding: "8px" }}>Started At</th>
                  </tr>
                </thead>
                <tbody>
                  {dashboardData.recent_scans.map((s) => (
                    <tr key={s.id} style={{ borderBottom: "1px solid #333" }}>
                      <td style={{ padding: "8px" }}>{s.scanner_type}</td>
                      <td style={{ padding: "8px" }}>{s.status}</td>
                      <td style={{ padding: "8px" }}>{s.started_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

       {activeTab === "network" && (
        <div>
          <h2>Network</h2>

          <h3>Active Hosts</h3>
          <table style={{ width: "100%", borderCollapse: "collapse", marginBottom: "2rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid #444" }}>
                <th style={{ padding: "8px" }}>IP Address</th>
                <th style={{ padding: "8px" }}>Hostname</th>
                <th style={{ padding: "8px" }}>Open Ports</th>
                <th style={{ padding: "8px" }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {networkHosts.map((h) => (
                <tr key={h.id} style={{ borderBottom: "1px solid #333" }}>
                  <td style={{ padding: "8px" }}>{h.ip_address}</td>
                  <td style={{ padding: "8px" }}>{h.hostname || "—"}</td>
                  <td style={{ padding: "8px" }}>{h.open_ports || "—"}</td>
                  <td style={{ padding: "8px" }}>{h.last_seen}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h3>Snort Alerts</h3>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid #444" }}>
                <th style={{ padding: "8px" }}>Severity</th>
                <th style={{ padding: "8px" }}>Source IP</th>
                <th style={{ padding: "8px" }}>Dest IP</th>
                <th style={{ padding: "8px" }}>Message</th>
                <th style={{ padding: "8px" }}>Created At</th>
              </tr>
            </thead>
            <tbody>
              {snortAlerts.map((a) => (
                <tr key={a.id} style={{ borderBottom: "1px solid #333" }}>
                  <td style={{ padding: "8px", color: severityColor(a.severity), fontWeight: "bold" }}>{a.severity}</td>
                  <td style={{ padding: "8px" }}>{a.source_ip}</td>
                  <td style={{ padding: "8px" }}>{a.dest_ip}</td>
                  <td style={{ padding: "8px" }}>{a.alert_message}</td>
                  <td style={{ padding: "8px" }}>{a.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {activeTab === "reports" && (
        <div>
          <h2>Reports</h2>

          <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1.5rem" }}>
            <button
              onClick={downloadPdfReport}
              style={{
                background: "#ef4444", color: "#fff", border: "none",
                padding: "8px 16px", borderRadius: "4px", cursor: "pointer",
              }}
            >
              Download PDF Report
            </button>
            <button
              onClick={() => {
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
              }}
              style={{
                background: "#22c55e", color: "#fff", border: "none",
                padding: "8px 16px", borderRadius: "4px", cursor: "pointer",
              }}
            >
              Download CSV Report
            </button>
          </div>

          <h3>Scan History</h3>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid #444" }}>
                <th style={{ padding: "8px" }}>Scanner</th>
                <th style={{ padding: "8px" }}>Status</th>
                <th style={{ padding: "8px" }}>Started At</th>
              </tr>
            </thead>
            <tbody>
              {scanHistory.map((s) => (
                <tr key={s.id} style={{ borderBottom: "1px solid #333" }}>
                  <td style={{ padding: "8px" }}>{s.scanner_type}</td>
                  <td style={{ padding: "8px" }}>{s.status}</td>
                  <td style={{ padding: "8px" }}>{s.started_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {activeTab === "vulnerabilities" && (
        <>
          <h2>Vulnerabilities</h2>

          <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{ padding: "6px", background: "#222", color: "#eee", border: "1px solid #444", borderRadius: "4px" }}
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <input
              type="text"
              placeholder="Search by title..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && fetchVulnerabilities()}
              style={{
                padding: "6px", background: "#222", color: "#eee",
                border: "1px solid #444", borderRadius: "4px", flexGrow: 1,
              }}
            />

            <button
              onClick={fetchVulnerabilities}
              style={{
                background: "#3b82f6", color: "#fff", border: "none",
                padding: "6px 16px", borderRadius: "4px", cursor: "pointer",
              }}
            >
              Search
            </button>

            <a
              href={`${API_BASE}/reports/vulnerabilities/csv`}
              onClick={(e) => {
                e.preventDefault();
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
              }}
              style={{
                background: "#22c55e", color: "#fff", border: "none",
                padding: "6px 16px", borderRadius: "4px", cursor: "pointer",
                textDecoration: "none", display: "inline-flex", alignItems: "center",
              }}
            >
              Download CSV
            </a>
          </div>

          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid #444" }}>
                <th style={{ padding: "8px" }}>Severity</th>
                <th style={{ padding: "8px" }}>Title</th>
                <th style={{ padding: "8px" }}>File</th>
                <th style={{ padding: "8px" }}>Line</th>
                <th style={{ padding: "8px" }}>AI Analysis</th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilities.map((v) => (
                <tr key={v.id} style={{ borderBottom: "1px solid #333" }}>
                  <td style={{ padding: "8px", color: severityColor(v.severity), fontWeight: "bold" }}>
                    {v.severity}
                  </td>
                  <td style={{ padding: "8px" }}>{v.title}</td>
                  <td style={{ padding: "8px" }}>{v.file_path}</td>
                  <td style={{ padding: "8px" }}>{v.line_number}</td>
                  <td style={{ padding: "8px" }}>
                    <button
                      onClick={() => viewAiReport(v.id)}
                      style={{
                        background: "#333", color: "#eee", border: "1px solid #555",
                        padding: "4px 10px", borderRadius: "4px", cursor: "pointer",
                      }}
                    >
                      {loadingId === v.id ? "Loading..." : "View"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {selectedReport && (
            <div style={{
              marginTop: "2rem", padding: "1.5rem", border: "1px solid #444",
              borderRadius: "8px", background: "#1a1a1a", maxWidth: "700px",
            }}>
              <h3>AI Analysis — Vulnerability #{selectedReport.vulnId}</h3>
              {selectedReport.detail ? (
                <p>{selectedReport.detail}</p>
              ) : (
                <>
                  <p><strong>Risk Score:</strong> {selectedReport.risk_score} / 10</p>
                  <p><strong>Summary:</strong> {selectedReport.summary}</p>
                  <p><strong>Remediation:</strong> {selectedReport.remediation}</p>
                </>
              )}
              <button
                onClick={() => setSelectedReport(null)}
                style={{
                  marginTop: "1rem", background: "#333", color: "#eee",
                  border: "1px solid #555", padding: "4px 10px", borderRadius: "4px", cursor: "pointer",
                }}
              >
                Close
              </button>
            </div>
          )}
        </>
      )}

      {activeTab === "assistant" && (
        <div style={{ maxWidth: "700px" }}>
          <h2>AI Assistant</h2>
          <p style={{ color: "#aaa" }}>Ask a security question, e.g. "What is SQL Injection?"</p>

          <div style={{
            border: "1px solid #333", borderRadius: "8px", background: "#1a1a1a",
            padding: "1rem", minHeight: "300px", maxHeight: "400px", overflowY: "auto", marginBottom: "1rem",
          }}>
            {chatMessages.length === 0 && (
              <p style={{ color: "#666" }}>No messages yet — ask something below.</p>
            )}
            {chatMessages.map((msg, i) => (
              <div
                key={i}
                style={{
                  marginBottom: "0.75rem",
                  textAlign: msg.role === "user" ? "right" : "left",
                }}
              >
                <span style={{
                  display: "inline-block", padding: "8px 12px", borderRadius: "8px",
                  background: msg.role === "user" ? "#3b82f6" : "#333",
                  color: "#fff", maxWidth: "80%",
                }}>
                  {msg.text}
                </span>
              </div>
            ))}
            {chatLoading && <p style={{ color: "#888" }}>Thinking...</p>}
          </div>

          <div style={{ display: "flex", gap: "0.5rem" }}>
            <input
              type="text"
              placeholder="Ask a security question..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && askAssistant()}
              style={{
                flexGrow: 1, padding: "8px", background: "#222", color: "#eee",
                border: "1px solid #444", borderRadius: "4px",
              }}
            />
            <button
              onClick={askAssistant}
              disabled={chatLoading}
              style={{
                background: "#3b82f6", color: "#fff", border: "none",
                padding: "8px 20px", borderRadius: "4px", cursor: "pointer",
              }}
            >
              Ask
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
