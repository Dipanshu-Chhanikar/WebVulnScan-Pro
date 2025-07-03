import { useState } from "react";
import axios from "axios";

export default function ScanForm() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("xss");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!target) return alert("Please enter a target URL.");
    setLoading(true);
    try {
      const res = await axios.post(
        `http://localhost:8000/scan/${scanType}?target=${encodeURIComponent(target)}`
      );
      setResult(res.data);
    } catch (err) {
      setResult({ error: err.message });
    }
    setLoading(false);
  };

  return (
    <div className="p-4 max-w-xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold text-center">WebVulnScan-Pro</h1>

      <input
        type="text"
        placeholder="Enter target URL (e.g. http://testphp.vulnweb.com)"
        className="w-full p-2 border rounded"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
      />

      <select
        className="w-full p-2 border rounded"
        value={scanType}
        onChange={(e) => setScanType(e.target.value)}
      >
        <option value="xss">XSS</option>
        <option value="csrf">CSRF</option>
        <option value="open-redirect">Open Redirect</option>
        <option value="security-headers">Security Headers</option>
        <option value="clickjacking">Clickjacking</option>
        <option value="all">Full Scan</option>
      </select>

      <button
        onClick={handleScan}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white p-2 rounded"
        disabled={loading}
      >
        {loading ? "Scanning..." : "Start Scan"}
      </button>

      {result && (
        <div className="mt-4 p-3 bg-gray-100 rounded text-sm whitespace-pre-wrap">
          <h2 className="font-semibold mb-2">Scan Result:</h2>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
