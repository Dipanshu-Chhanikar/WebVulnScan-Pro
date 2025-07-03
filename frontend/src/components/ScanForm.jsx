import { useState, useRef } from "react";
import axios from "axios";

export default function ScanForm() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("xss");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const controllerRef = useRef(null);  // Holds AbortController instance

  const handleScan = async () => {
    if (!target) return alert("Please enter a target URL.");
    setLoading(true);
    setResult(null);
    setScanStatus("");

    // Create a new AbortController
    const controller = new AbortController();
    controllerRef.current = controller;

    try {
      if (scanType === "all") {
        const fullResult = { target };

        setScanStatus("🔍 Scanning for XSS...");
        fullResult.xss = (await axios.post(
          `http://localhost:8000/scan/xss?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("💉 Scanning for SQL Injection...");
        fullResult.sql_injection = (await axios.post(
          `http://localhost:8000/scan/sqli?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("🔓 Scanning for CSRF...");
        fullResult.csrf = (await axios.post(
          `http://localhost:8000/scan/csrf?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("🔁 Scanning for Open Redirect...");
        fullResult.open_redirect = (await axios.post(
          `http://localhost:8000/scan/open-redirect?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("📭 Checking Security Headers...");
        fullResult.security_headers = (await axios.post(
          `http://localhost:8000/scan/security-headers?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("🎯 Scanning for Clickjacking...");
        fullResult.clickjacking = (await axios.post(
          `http://localhost:8000/scan/clickjacking?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("🗂️ Scanning for Path Traversal...");
        fullResult.path_traversal = (await axios.post(
          `http://localhost:8000/scan/path-traversal?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("💣 Scanning for Remote Code Execution...");
        fullResult.rce = (await axios.post(
          `http://localhost:8000/scan/rce?target=${encodeURIComponent(target)}`,
          {},
          { signal: controller.signal }
        )).data;

        setScanStatus("✅ Full Scan Complete.");
        setResult(fullResult);
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
          {loading ? `⏳ ${scanStatus}` : scanStatus}
        </div>
      )}

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
                      {value.duration ? `⏱️ Duration: ${value.duration}\n` : ""}
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
