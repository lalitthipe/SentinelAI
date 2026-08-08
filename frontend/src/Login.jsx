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
    <div className="login-shell">
      <form onSubmit={handleSubmit} className="login-card">
        <div className="login-brand">
          <div className="brand-mark">S</div>
          <div>
            <p className="login-title">SentinelAI</p>
            <p className="login-sub">SOC ACCESS PORTAL</p>
          </div>
        </div>

        <label className="field-label">Username</label>
        <input
          type="text"
          className="text-input"
          style={{ width: "100%", marginBottom: "14px" }}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />

        <label className="field-label">Password</label>
        <input
          type="password"
          className="text-input"
          style={{ width: "100%", marginBottom: "18px" }}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        {error && <p className="login-error">{error}</p>}

        <button type="submit" disabled={loading} className="btn btn-primary" style={{ width: "100%" }}>
          {loading ? "Authenticating..." : "Log In"}
        </button>
      </form>
    </div>
  );
}

export default Login;
