import { useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanHistory from "./components/ScanHistory";

export default function App() {
  const [view, setView] = useState("scan");

  return (
    <div className="min-h-screen bg-gray-50 text-black p-4">
      <div className="flex justify-center mb-4 gap-4">
        <button onClick={() => setView("scan")} className="px-4 py-2 bg-blue-600 text-white rounded">Scan</button>
        <button onClick={() => setView("history")} className="px-4 py-2 bg-gray-700 text-white rounded">History</button>
      </div>
      {view === "scan" ? <ScanForm /> : <ScanHistory />}
    </div>
  );
}
