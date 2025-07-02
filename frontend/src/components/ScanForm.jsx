import { useState } from "react";
import axios from "axios";

export default function ScanForm() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);

  const startScan = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${import.meta.env.VITE_API_BASE}/scan/sqli?target=${url}`);
      setResult(response.data.details);
    } catch (err) {
      setResult("Error running scan.");
    }
    setLoading(false);
  };

  return (
    <div className="max-w-xl mx-auto mt-10 p-6 bg-white shadow-xl rounded-2xl space-y-4">
      <h1 className="text-xl font-bold">SQL Injection Scanner</h1>
      <input
        type="text"
        placeholder="Enter target URL"
        className="w-full p-2 border rounded"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />
      <button
        onClick={startScan}
        disabled={loading}
        className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
      >
        {loading ? "Scanning..." : "Start Scan"}
      </button>
      {result && (
        <pre className="bg-gray-100 p-4 rounded max-h-[400px] overflow-auto">{result}</pre>
      )}
    </div>
  );
}
