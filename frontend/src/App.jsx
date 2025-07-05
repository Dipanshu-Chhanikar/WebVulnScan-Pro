import { useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanHistory from "./components/ScanHistory";
import Documentation from "./components/Documentation";
import Vulnerabilities from "./components/Vulnerabilities";
import About from "./components/About";

export default function App() {
  const [view, setView] = useState("home");

  return (
    <div className="min-h-screen w-full bg-gray-950 text-white flex flex-col">
      {/* Navbar */}
      <nav className="w-full bg-gray-900 text-white shadow-md">
        <div className="flex justify-between items-center px-8 py-4">
          <div className="text-xl font-bold text-blue-400">🛡️ WebVulnScan-Pro</div>
          <div className="flex flex-wrap gap-4">
            {[
              "Home",
              "Scan",
              "Results",
              "Vulnerabilities",
              "Documentation",
              "About",
              "Contact",
            ].map((item) => (
              <button
                key={item}
                onClick={() => setView(item.toLowerCase())}
                className={`text-sm px-4 py-2 rounded hover:bg-blue-600 transition ${
                  view === item.toLowerCase() ? "bg-blue-700" : ""
                }`}
              >
                {item}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-grow w-full px-10 py-12">
        {view === "home" && (
          <div className="text-center">
            <h1 className="text-4xl font-bold text-blue-500 mb-4">
              Welcome to WebVulnScan-Pro
            </h1>
            <p className="text-lg text-gray-300">
              A powerful web vulnerability scanner built with FastAPI, React, MongoDB, and TailwindCSS.
            </p>
            <p className="text-sm text-gray-400 mt-2">
              Use the top navigation to start a scan, check reports, or learn more.
            </p>
          </div>
        )}

        {view === "scan" && (
          <div className="max-w-2xl mx-auto">
            <h2 className="text-3xl font-semibold text-blue-400 mb-4">Start a Scan</h2>
            <ScanForm />
          </div>
        )}

        {view === "results" && (
          <div className="max-w-3xl mx-auto">
            <h2 className="text-3xl font-semibold text-blue-400 mb-4">Scan Results</h2>
            <ScanHistory />
          </div>
        )}

        {view === "documentation" && <Documentation />}

        {view === "vulnerabilities" && <Vulnerabilities />}

        {view === "about" && <About />}

        {["contact"].includes(view) && (
          <div className="text-center text-gray-400 text-lg">
            📄 {view.charAt(0).toUpperCase() + view.slice(1)} page coming soon...
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="w-full bg-gray-900 text-center text-sm text-gray-500 py-4">
        © 2025 WebVulnScan-Pro — All rights reserved
      </footer>
    </div>
  );
}
