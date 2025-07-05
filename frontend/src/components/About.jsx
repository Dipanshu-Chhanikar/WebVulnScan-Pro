export default function About() {
  return (
    <div className="max-w-4xl mx-auto text-gray-300">
      <h2 className="text-4xl font-bold text-blue-400 mb-6">About WebVulnScan-Pro</h2>

      <p className="mb-6 text-lg">
        <span className="font-semibold text-white">WebVulnScan-Pro</span> is a comprehensive web vulnerability scanner built for developers, bug bounty hunters, and security analysts. It was designed to detect a wide range of real-world vulnerabilities using advanced payloads, form fuzzing, and heuristic analysis.
      </p>

      <h3 className="text-2xl text-blue-300 font-semibold mb-2">🔧 Technology Stack</h3>
      <ul className="list-disc list-inside ml-4 mb-6">
        <li><span className="font-medium text-white">Frontend:</span> React + Vite + TailwindCSS</li>
        <li><span className="font-medium text-white">Backend:</span> FastAPI</li>
        <li><span className="font-medium text-white">Database:</span> MongoDB Atlas</li>
      </ul>

      <h3 className="text-2xl text-blue-300 font-semibold mb-2">🛠️ Key Features</h3>
      <ul className="list-disc list-inside ml-4 mb-6">
        <li>Advanced scanners for XSS, SQLi, RCE, Path Traversal, CSRF, and more</li>
        <li>Real-time progress updates and duration tracking</li>
        <li>Rich UI with detailed scan history and vulnerability grouping</li>
        <li>PDF & TXT export for professional reporting</li>
      </ul>

      <h3 className="text-2xl text-blue-300 font-semibold mb-2">🎯 Project Goal</h3>
      <p className="mb-4">
        The aim of WebVulnScan-Pro is to provide an open-source, extensible, and easy-to-use platform that simulates real-world attack scenarios and helps users identify common web vulnerabilities quickly.
      </p>

      <p className="text-sm text-gray-500 italic">
        Created with ❤️ by Dipanshu Chhanikar
      </p>
    </div>
  );
}
