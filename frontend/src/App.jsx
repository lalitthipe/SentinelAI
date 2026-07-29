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
    </div>
  );
}

export default App;
