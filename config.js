// MedGate Sentinel API base. Local development: same machine. Production: the Render API.
const API_BASE = location.origin.includes("localhost") || location.hostname === "127.0.0.1"
  ? "http://localhost:5000"
  : "https://medgate-sentinel.onrender.com";
