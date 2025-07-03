import { useEffect, useState } from "react";
import axios from "axios";

export default function ScanHistory() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    axios.get("http://localhost:8000/history")
      .then(res => setHistory(res.data))
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="p-4 max-w-5xl mx-auto">
      <h2 className="text-xl font-bold mb-4">🕓 Scan History</h2>
      {history.length === 0 ? (
        <p className="text-gray-600">No scans yet.</p>
      ) : (
        <div className="space-y-3">
          {history.map((item, i) => (
            <div key={i} className="border p-3 rounded bg-white shadow">
              <div><strong>Type:</strong> {item.type}</div>
              <div><strong>Target:</strong> {item.target}</div>
              <div><strong>Time:</strong> {new Date(item.timestamp.$date).toLocaleString()}</div>
              <details className="mt-2">
                <summary className="cursor-pointer text-blue-600">View Details</summary>
                <pre className="bg-gray-100 p-2 rounded text-sm whitespace-pre-wrap">
                  {JSON.stringify(item.result, null, 2)}
                </pre>
              </details>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
