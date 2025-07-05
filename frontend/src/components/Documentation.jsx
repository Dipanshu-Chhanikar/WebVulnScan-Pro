export default function Documentation() {
  return (
    <div className="prose prose-invert max-w-4xl mx-auto text-gray-300">
      <h1 className="text-blue-400 text-4xl font-bold mb-6">📚 Documentation</h1>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-white">Overview</h2>
        <p>
          WebVulnScan-Pro is a full-stack advanced web vulnerability scanner designed for penetration testers, bug bounty hunters, and security researchers. Built with FastAPI, React, TailwindCSS, and MongoDB, it offers real-time scanning, grouped vulnerability results, exportable reports, and a clean modern UI.
        </p>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-white">Supported Vulnerabilities</h2>
        <ul className="list-disc list-inside">
          <li>Cross-Site Scripting (XSS)</li>
          <li>SQL Injection (SQLi)</li>
          <li>Command Injection (RCE)</li>
          <li>Path Traversal</li>
          <li>Cross-Site Request Forgery (CSRF)</li>
          <li>Open Redirect</li>
          <li>Clickjacking</li>
          <li>Security Headers Misconfiguration</li>
          <li>Meta Redirect and CSP Frame-Ancestors Issues</li>
        </ul>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-white">How to Use</h2>
        <ol className="list-decimal list-inside">
          <li>Navigate to the <strong>Scan</strong> tab and enter a target URL.</li>
          <li>Select a scan type (individual or full scan).</li>
          <li>Click "Start Scan" to initiate the process.</li>
          <li>Monitor real-time scanning progress and status.</li>
          <li>View detailed results in the <strong>Results</strong> tab.</li>
          <li>Export results as PDF or TXT, or copy JSON.</li>
        </ol>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-white">Tech Stack</h2>
        <ul className="list-disc list-inside">
          <li>⚙️ <strong>Backend</strong>: FastAPI (Python)</li>
          <li>🎨 <strong>Frontend</strong>: React + TailwindCSS</li>
          <li>🗃️ <strong>Database</strong>: MongoDB Atlas</li>
          <li>🛠️ <strong>PDF Export</strong>: jsPDF</li>
        </ul>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-white">Upcoming Features</h2>
        <ul className="list-disc list-inside">
          <li>SSRF, CORS, Deserialization, Host Header Injection scanners</li>
          <li>JWT Analyzer</li>
          <li>Cloud config misconfiguration detection</li>
          <li>Live progress bar and error handling enhancements</li>
        </ul>
      </section>

      <p className="text-sm text-gray-400 mt-10">
        ✨ Built with ❤️ by Dipanshu Chhanikar — <a href="https://github.com/Dipanshu-Chhanikar/WebVulnScan-Pro" className="text-blue-400 underline">View Source on GitHub</a>
      </p>
    </div>
  );
}
