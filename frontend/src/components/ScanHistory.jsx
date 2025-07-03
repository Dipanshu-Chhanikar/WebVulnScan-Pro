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
    text.replace(/[\u{1F300}-\u{1F6FF}]/gu, "").replace(/[^\x00-\x7F]/g, "");

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
    writeLine(`Scan Type: ${stripEmojis(item.type)}`);
    writeLine(`Target: ${item.target}`);
    writeLine(`Time: ${new Date(item.timestamp.$date).toLocaleString()}`);
    writeLine("");
    writeLine("Scan Result:", true);
    writeLine("");

    if (item.type === "FULL" && typeof item.result === "object") {
      Object.entries(item.result).forEach(([key, value]) => {
        if (key !== "target") {
          writeLine(`${key.replace(/_/g, " ")} Result`, true);
          const jsonLines = JSON.stringify(value, null, 2).split("\n");
          jsonLines.forEach(line => writeLine(line));
          writeLine("");
        }
      });
    } else {
      const jsonLines = JSON.stringify(item.result, null, 2).split("\n");
      jsonLines.forEach(line => writeLine(line));
    }

    doc.save(`${item.type.replace(/\s+/g, "_")}_Report.pdf`);
  };

  const exportAsText = (item) => {
    let content = `WebVulnScan-Pro Report\n\n`;
    content += `Scan Type: ${stripEmojis(item.type)}\n`;
    content += `Target: ${item.target}\n`;
    content += `Time: ${new Date(item.timestamp.$date).toLocaleString()}\n\n`;
    content += `Scan Result:\n\n`;

    if (item.type === "FULL" && typeof item.result === "object") {
      Object.entries(item.result).forEach(([key, value]) => {
        if (key !== "target") {
          content += `${key.replace(/_/g, " ")} Result:\n`;
          content += JSON.stringify(value, null, 2) + "\n\n";
        }
      });
    } else {
      content += JSON.stringify(item.result, null, 2);
    }

    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${item.type.replace(/\s+/g, "_")}_Report.txt`;
    link.click();
    URL.revokeObjectURL(url);
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
                  {/* ✅ Scan Result heading + 📋 Copy JSON */}
                  <div className="flex justify-between items-center mb-2">
                    <h2 className="font-bold text-blue-700 dark:text-blue-400">
                      ✅ Scan Result:
                    </h2>
                    <button
                      onClick={() =>
                        navigator.clipboard.writeText(JSON.stringify(item.result, null, 2))
                      }
                      className="bg-gray-700 hover:bg-gray-800 text-white px-3 py-1 text-sm rounded"
                    >
                      📋 Copy JSON
                    </button>
                  </div>

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

                  {/* 📥 Download PDF + 📄 Export TXT buttons */}
                  <div className="mt-4 flex gap-2">
                    <button
                      onClick={() => generatePDF(item)}
                      className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                    >
                      📥 Download PDF
                    </button>
                    <button
                      onClick={() => exportAsText(item)}
                      className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded"
                    >
                      📄 Export as .txt
                    </button>
                  </div>
                </div>
              </details>
            </div>
          );
        })
      )}
    </div>
  );
}
