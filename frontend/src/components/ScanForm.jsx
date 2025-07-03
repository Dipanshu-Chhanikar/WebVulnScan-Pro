import { useState, useRef } from "react";
import axios from "axios";

export default function ScanForm() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("xss");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const controllerRef = useRef(null); // Holds AbortController instance

  const handleScan = async () => {
    if (!target) return alert("Please enter a target URL.");
    setLoading(true);
    setResult(null);
    setScanStatus("");

    const controller = new AbortController();
    controllerRef.current = controller;

    try {
      if (scanType === "all") {
        setScanStatus("⏳ 🔍 Starting full scan...");
        const start = Date.now();

        const res = await axios.post(
          `http://localhost:8000/scan/all?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        );

        const fullResult = res.data;
        const totalDuration = (Date.now() - start) / 1000;
        fullResult.total_duration = `${totalDuration.toFixed(2)}s`;

        setResult(fullResult);
        setScanStatus("✅ Full Scan Complete.");
      } else {
        setScanStatus(`🕵️‍♂️ Scanning for ${scanType.toUpperCase()}...`);
        const res = await axios.post(
          `http://localhost:8000/scan/${scanType}?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        );
        setResult(res.data);
        setScanStatus("✅ Scan complete.");
      }
    } catch (err) {
      if (axios.isCancel(err) || err.name === "CanceledError") {
        setScanStatus("❌ Scan cancelled.");
      } else {
        setResult({ error: err.message });
        setScanStatus("❌ Scan failed.");
      }
    }

    setLoading(false);
    controllerRef.current = null;
  };

  const cancelScan = () => {
    if (controllerRef.current) {
      controllerRef.current.abort();
      setLoading(false);
      setScanStatus("❌ Scan cancelled.");
    }
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

      <div className="flex gap-2">
        <button
          onClick={handleScan}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-lg font-semibold"
          disabled={loading}
        >
          {loading ? "🔄 Scanning..." : "🚀 Start Scan"}
        </button>

        {loading && (
          <button
            onClick={cancelScan}
            className="w-full bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg font-semibold"
          >
            ❌ Cancel
          </button>
        )}
      </div>

      {scanStatus && (
        <div className={`text-sm mt-2 ${loading ? "text-gray-500 animate-pulse" : "text-green-600"}`}>
          {loading ? `${scanStatus}` : scanStatus}
        </div>
      )}

      {result && (
        <div className="mt-4 p-3 bg-gray-100 dark:bg-gray-800 rounded-lg overflow-x-auto text-sm max-h-[600px]">
          <h2 className="font-bold mb-2 text-blue-700 dark:text-blue-400">✅ Scan Result:</h2>

          {scanType === "all" && typeof result === "object" ? (
            <div className="space-y-4">
              {Object.entries(result).map(([key, value]) =>
                key !== "target" && key !== "total_duration" ? (
                  <div key={key} className="border border-gray-700 rounded p-3 bg-gray-900">
                    <h3 className="font-bold text-blue-400 capitalize mb-2">
                      {key.replace(/_/g, " ")} Result
                    </h3>
                    <pre className="text-gray-200 whitespace-pre-wrap">
                      {value?.duration ? `⏱️ Duration: ${value.duration}\n` : ""}
                      {JSON.stringify(value, null, 2)}
                    </pre>
                  </div>
                ) : null
              )}
              {result.total_duration && (
                <div className="text-sm text-right font-semibold text-green-500">
                  ⏳ Total Duration: {result.total_duration}
                </div>
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
