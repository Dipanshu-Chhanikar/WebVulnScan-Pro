export default function Navbar({ view, setView }) {
  return (
    <nav className="bg-white dark:bg-gray-900 shadow px-6 py-4 flex justify-between items-center rounded-xl">
      <h1 className="text-xl font-bold text-blue-600 dark:text-blue-400">
        🛡️ WebVulnScan-Pro
      </h1>
      <div className="flex gap-4">
        <button
          onClick={() => setView("scan")}
          className={`px-4 py-2 rounded-full font-medium ${
            view === "scan"
              ? "bg-blue-600 text-white"
              : "bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200"
          }`}
        >
          🔍 Scan
        </button>
        <button
          onClick={() => setView("history")}
          className={`px-4 py-2 rounded-full font-medium ${
            view === "history"
              ? "bg-blue-600 text-white"
              : "bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200"
          }`}
        >
          🕓 History
        </button>
      </div>
    </nav>
  );
}
