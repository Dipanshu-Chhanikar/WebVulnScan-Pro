import { useEffect, useState } from "react";
import axios from "axios";
import jsPDF from "jspdf";

// Severity levels and icons
const severityLevels = {
  "XSS": "High",
  "SQL Injection": "High",
  "CSRF": "Medium",
  "Open Redirect": "Low",
  "Security Headers": "Low",
  "Clickjacking": "Medium",
  "Path Traversal": "High",
  "Remote Code Execution": "Critical",
  "FULL": "Mixed"
};

const icons = {
  "XSS": "🧪",
  "SQL Injection": "💉",
  "CSRF": "🔓",
  "Open Redirect": "🔁",
  "Security Headers": "📭",
  "Clickjacking": "🎯",
  "Path Traversal": "🗂️",
  "Remote Code Execution": "💣",
  "FULL": "🛡️"
};

const severityColor = {
  "Critical": "bg-red-800",
  "High": "bg-red-600",
  "Medium": "bg-yellow-600",
  "Low": "bg-green-600",
  "Mixed": "bg-purple-600"
};

export default function ScanHistory() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    axios.get("http://localhost:8000/history")
      .then(res => setHistory(res.data))
      .catch(err => console.error(err));
  }, []);

  const stripEmojis = (text) =>
    text.replace(/[\u{1F300}-\u{1F6FF}]/gu, "");

  const generatePDF = (item) => {
    const doc = new jsPDF({ unit: "pt", format: "a4", orientation: "portrait" });
    const margin = 40;
    const lineHeight = 18;
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    let y = margin;

    const writeLine = (text, bold = false) => {
      if (y + lineHeight > pageHeight - margin) {
        doc.addPage();
        y = margin;
      }
      doc.setFont("helvetica", bold ? "bold" : "normal");
      const safeText = stripEmojis(text);
      const lines = doc.splitTextToSize(safeText, pageWidth - 2 * margin);
      lines.forEach(line => {
        doc.text(line, margin, y);
        y += lineHeight;
      });
    };

    writeLine("WebVulnScan-Pro Report", true);
    writeLine("");
    writeLine(`Scan Type: ${item.type}`);
    writeLine(`Target: ${item.target}`);
    writeLine(`Time: ${new Date(item.timestamp.$date).toLocaleString()}`);
    writeLine("");
    writeLine("Scan Result:", true);

    const resultText = JSON.stringify(item.result, null, 2).split("\n");
    resultText.forEach(line => writeLine(line));

    doc.save(`${item.type.replace(/\s+/g, "_")}_Report.pdf`);
  };

  const renderVulnerabilitySection = (key, data) => (
    <div key={key} className="border border-gray-700 rounded p-3 bg-gray-900">
      <h3 className="font-bold text-blue-400 capitalize mb-2">
        {key.replace(/_/g, " ")} Result
      </h3>
      <pre className="text-gray-200 whitespace-pre-wrap">
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
  );

  return (
    <div className="space-y-4">
      {history.length === 0 ? (
        <p className="text-gray-500 text-sm">No scan history available yet.</p>
      ) : (
        history.map((item, i) => {
          const type = item.type;
          const icon = icons[type] || "📄";
          const severity = severityLevels[type] || "Info";
          const colorClass = severityColor[severity] || "bg-gray-500";

          return (
            <div
              key={i}
              className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg shadow-sm"
            >
              <div className="flex justify-between items-center">
                <div className="text-lg font-semibold text-blue-500">
                  {icon} {type}
                </div>
                <span className={`text-xs text-white px-2 py-1 rounded ${colorClass}`}>
                  {severity}
                </span>
              </div>

              <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mt-2">
                <span className="block">
                  🌐 <strong>Target:</strong> {item.target}
                </span>
                <span className="block">
                  🕒 <strong>Time:</strong> {new Date(item.timestamp.$date).toLocaleString()}
                </span>
              </div>

              <details className="mt-2">
                <summary className="cursor-pointer text-blue-600">
                  View Result
                </summary>

                <div className="mt-4 p-3 bg-gray-100 dark:bg-gray-800 rounded-lg overflow-x-auto text-sm max-h-[600px]">
                  <h2 className="font-bold mb-2 text-blue-700 dark:text-blue-400">✅ Scan Result:</h2>

                  {type === "FULL" && typeof item.result === "object" ? (
                    <div className="space-y-4">
                      {Object.entries(item.result).map(([key, value]) =>
                        key !== "target" ? renderVulnerabilitySection(key, value) : null
                      )}
                    </div>
                  ) : (
                    <div className="border border-gray-700 rounded p-3 bg-gray-900">
                      <h3 className="font-bold text-blue-400 capitalize mb-2">
                        {type} Result
                      </h3>
                      <pre className="text-gray-200 whitespace-pre-wrap">
                        {JSON.stringify(item.result, null, 2)}
                      </pre>
                    </div>
                  )}

                  <button
                    onClick={() => generatePDF(item)}
                    className="mt-4 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                  >
                    📥 Download PDF
                  </button>
                </div>
              </details>
            </div>
          );
        })
      )}
    </div>
  );
}
