import { useState } from "react";

const API_BASE = "http://192.168.56.101:8000";

function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    const formBody = new URLSearchParams();
    formBody.append("username", username);
    formBody.append("password", password);

    fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formBody,
    })
      .then((res) => res.json())
      .then((data) => {
        setLoading(false);
        if (data.access_token) {
          onLoginSuccess(data.access_token);
        } else {
          setError(data.detail || "Login failed");
        }
      })
      .catch(() => {
        setLoading(false);
        setError("Could not reach backend");
      });
  };

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        background: "#111",
        fontFamily: "sans-serif",
      }}
    >
      <form
        onSubmit={handleSubmit}
        style={{
          background: "#1a1a1a",
          padding: "2rem",
          borderRadius: "8px",
          border: "1px solid #333",
          width: "320px",
          color: "#eee",
        }}
      >
        <h2 style={{ marginTop: 0 }}>SentinelAI Login</h2>

        <label style={{ display: "block", marginBottom: "4px" }}>Username</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{
            width: "100%",
            padding: "8px",
            marginBottom: "1rem",
            background: "#222",
            border: "1px solid #444",
            borderRadius: "4px",
            color: "#eee",
            boxSizing: "border-box",
          }}
          required
        />

        <label style={{ display: "block", marginBottom: "4px" }}>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{
            width: "100%",
            padding: "8px",
            marginBottom: "1rem",
            background: "#222",
            border: "1px solid #444",
            borderRadius: "4px",
            color: "#eee",
            boxSizing: "border-box",
          }}
          required
        />

        {error && <p style={{ color: "#ff6b6b" }}>{error}</p>}

        <button
          type="submit"
          disabled={loading}
          style={{
            width: "100%",
            padding: "10px",
            background: "#3b82f6",
            border: "none",
            borderRadius: "4px",
            color: "#fff",
            cursor: "pointer",
            fontWeight: "bold",
          }}
        >
          {loading ? "Logging in..." : "Log In"}
        </button>
      </form>
    </div>
  );
}

export default Login;
