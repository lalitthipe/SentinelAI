import { useEffect, useState } from "react";

function App() {
  const [status, setStatus] = useState("checking...");

  useEffect(() => {
    fetch("http://192.168.56.101:8000/health")
      .then((res) => res.json())
      .then((data) => setStatus(data.status))
      .catch(() => setStatus("could not reach backend"));
  }, []);

  return (
    <div style={{ fontFamily: "sans-serif", padding: "2rem" }}>
      <h1>SentinelAI</h1>
      <p>Backend status: {status}</p>
    </div>
  );
}

export default App;
