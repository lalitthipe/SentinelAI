import { useEffect, useState } from "react";

const API_BASE = "http://192.168.56.101:8000";

function App() {
  const [status, setStatus] = useState("checking...");
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);
  const [loadingId, setLoadingId] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then((res) => res.json())
      .then((data) => setStatus(data.status))
      .catch(() => setStatus("could not reach backend"));

    fetch(`${API_BASE}/vulnerabilities`)
      .then((res) => res.json())
      .then((data) => setVulnerabilities(data))
      .catch(() => setVulnerabilities([]));
  }, []);

  const viewAiReport = (vulnId) => {
    setLoadingId(vulnId);
    fetch(`${API_BASE}/vulnerabilities/${vulnId}/ai-report`)
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

  return (
    <div style={{ fontFamily: "sans-serif", padding: "2rem", color: "#eee", background: "#111", minHeight: "100vh" }}>
      <h1>SentinelAI</h1>
      <p>Backend status: {status}</p>

      <h2>Vulnerabilities</h2>
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
                    background: "#333",
                    color: "#eee",
                    border: "1px solid #555",
                    padding: "4px 10px",
                    borderRadius: "4px",
                    cursor: "pointer",
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
        <div
          style={{
            marginTop: "2rem",
            padding: "1.5rem",
            border: "1px solid #444",
            borderRadius: "8px",
            background: "#1a1a1a",
            maxWidth: "700px",
          }}
        >
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
              marginTop: "1rem",
              background: "#333",
              color: "#eee",
              border: "1px solid #555",
              padding: "4px 10px",
              borderRadius: "4px",
              cursor: "pointer",
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
