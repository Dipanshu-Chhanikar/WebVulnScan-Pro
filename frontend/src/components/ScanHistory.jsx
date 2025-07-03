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
    <div className="space-y-4">
      {history.length === 0 ? (
        <p className="text-gray-500 text-sm">No scan history available yet.</p>
      ) : (
        history.map((item, i) => (
          <div key={i} className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg shadow-sm">
            <div className="text-sm font-medium text-gray-700 dark:text-gray-300">
              <span className="block">🔍 <strong>Type:</strong> {item.type}</span>
              <span className="block">🌐 <strong>Target:</strong> {item.target}</span>
              <span className="block">🕒 <strong>Time:</strong> {new Date(item.timestamp.$date).toLocaleString()}</span>
            </div>
            <details className="mt-2">
              <summary className="cursor-pointer text-blue-600">View Result</summary>
              <pre className="mt-2 bg-gray-200 dark:bg-gray-700 p-2 rounded text-sm overflow-x-auto">
                {JSON.stringify(item.result, null, 2)}
              </pre>
            </details>
          </div>
        ))
      )}
    </div>
  );
}
