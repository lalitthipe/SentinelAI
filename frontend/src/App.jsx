import { useEffect, useState } from "react";

function App() {
  const [status, setStatus] = useState("checking...");
  const [vulnerabilities, setVulnerabilities] = useState([]);

  useEffect(() => {
    fetch("http://192.168.56.101:8000/health")
      .then((res) => res.json())
      .then((data) => setStatus(data.status))
      .catch(() => setStatus("could not reach backend"));

    fetch("http://192.168.56.101:8000/vulnerabilities")
      .then((res) => res.json())
      .then((data) => setVulnerabilities(data))
      .catch(() => setVulnerabilities([]));
  }, []);

  return (
    <div style={{ fontFamily: "sans-serif", padding: "2rem", color: "#eee", background: "#111", minHeight: "100vh" }}>
      <h1>SentinelAI</h1>
      <p>Backend status: {status}</p>

      <h2>Vulnerabilities</h2>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ textAlign: "left", borderBottom: "1px solid #444" }}>
            <th>Severity</th>
            <th>Title</th>
            <th>File</th>
            <th>Line</th>
          </tr>
        </thead>
        <tbody>
          {vulnerabilities.map((v) => (
            <tr key={v.id} style={{ borderBottom: "1px solid #333" }}>
              <td>{v.severity}</td>
              <td>{v.title}</td>
              <td>{v.file_path}</td>
              <td>{v.line_number}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
