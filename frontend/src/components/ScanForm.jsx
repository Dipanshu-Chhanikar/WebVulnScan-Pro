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
    <div className="space-y-4">
      <input
        type="text"
        placeholder="Enter target URL (e.g. http://testphp.vulnweb.com)"
        className="w-full p-3 border rounded-lg bg-gray-100 dark:bg-gray-800 dark:border-gray-700 text-black dark:text-white"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
      />

      <select
        className="w-full p-3 border rounded-lg bg-gray-100 dark:bg-gray-800 dark:border-gray-700 text-black dark:text-white"
        value={scanType}
        onChange={(e) => setScanType(e.target.value)}
      >
        <option value="xss">XSS</option>
        <option value="csrf">CSRF</option>
        <option value="sqli">SQL Injection</option>
        <option value="path-traversal">Path Traversal</option>
        <option value="rce">Remote Code Execution</option>
        <option value="open-redirect">Open Redirect</option>
        <option value="security-headers">Security Headers</option>
        <option value="clickjacking">Clickjacking</option>
        <option value="all">Full Scan</option>
      </select>

      <button
        onClick={handleScan}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-lg font-semibold"
        disabled={loading}
      >
        {loading ? "🔄 Scanning..." : "🚀 Start Scan"}
      </button>

      {result && (
        <div className="mt-4 p-3 bg-gray-100 dark:bg-gray-800 rounded-lg overflow-x-auto text-sm max-h-[600px]">
          <h2 className="font-bold mb-2 text-blue-700 dark:text-blue-400">✅ Scan Result:</h2>

          {scanType === "all" && typeof result === "object" ? (
            <div className="space-y-4">
              {Object.entries(result).map(([key, value]) =>
                key !== "target" ? (
                  <div key={key} className="border border-gray-700 rounded p-3 bg-gray-900">
                    <h3 className="font-bold text-blue-400 capitalize mb-2">
                      {key.replace(/_/g, " ")} Result
                    </h3>
                    <pre className="text-gray-200 whitespace-pre-wrap">
                      {JSON.stringify(value, null, 2)}
                    </pre>
                  </div>
                ) : null
              )}
            </div>
          ) : (
            <pre>{JSON.stringify(result, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  );
}
