// src/components/Vulnerabilities.jsx

export default function Vulnerabilities() {
    const vulns = [
        {
            name: "Cross-Site Scripting (XSS)",
            severity: "High",
            description:
                "XSS allows attackers to inject malicious JavaScript into web pages viewed by other users, enabling cookie theft, keylogging, or session hijacking.",
            example: `https://example.com/search?q=<script>alert(1)</script>`,
        },
        {
            name: "SQL Injection (SQLi)",
            severity: "Critical",
            description:
                "SQLi lets attackers manipulate backend SQL queries to access, modify, or destroy database data by injecting crafted payloads.",
            example: `https://example.com/login?user=admin'--`,
        },
        {
            name: "Remote Code Execution (RCE)",
            severity: "Critical",
            description:
                "RCE occurs when user input is executed as system-level commands, allowing attackers to gain shell access or take control of the server.",
            example: `https://example.com/ping?host=127.0.0.1;whoami`,
        },
        {
            name: "Path Traversal",
            severity: "High",
            description:
                "Path Traversal enables attackers to access arbitrary files outside the intended directory by manipulating path parameters.",
            example: `https://example.com/view?file=../../../../etc/passwd`,
        },
        {
            name: "Cross-Site Request Forgery (CSRF)",
            severity: "Medium",
            description:
                "CSRF tricks authenticated users into submitting unwanted actions (like changing passwords) without their consent.",
            example: `A hidden form auto-submitted via <img> or <script> tags.`,
        },
        {
            name: "Open Redirect",
            severity: "Low",
            description:
                "An attacker can redirect users to a malicious site by manipulating redirect parameters in the URL.",
            example: `https://example.com/redirect?url=http://evil.com`,
        },
        {
            name: "Clickjacking",
            severity: "Medium",
            description:
                "Clickjacking tricks users into clicking on hidden or disguised elements by overlaying transparent iframes.",
            example: `Malicious page embeds your site in an invisible iframe.`,
        },
        {
            name: "Missing Security Headers",
            severity: "Low",
            description:
                "Missing HTTP headers like X-Content-Type-Options, X-Frame-Options, or CSP can leave the app open to multiple attacks.",
            example: `Response lacks 'X-Frame-Options: DENY'`,
        },
        {
            name: "Weak Meta Refresh / CSP Fallbacks",
            severity: "Low",
            description: `Vulnerable use of <meta http-equiv="refresh"> or CSP frame-ancestors fallback can lead to open redirect or clickjacking.`,
            example: `<meta http-equiv="refresh" content="0;url=http://evil.com">`,
        }

    ];

    return (
        <div className="max-w-5xl mx-auto text-gray-200">
            <h1 className="text-4xl font-bold text-blue-400 mb-8">🛡️ Supported Vulnerabilities</h1>

            {vulns.map((vuln, idx) => (
                <div key={idx} className="mb-6 border-b border-gray-700 pb-4">
                    <h2 className="text-2xl font-semibold text-white">{vuln.name}</h2>
                    <p className="text-sm text-blue-300 font-semibold">Severity: {vuln.severity}</p>
                    <p className="mt-2">{vuln.description}</p>
                    {vuln.example && (
                        <div className="mt-2 text-sm text-gray-400">
                            <strong>Example:</strong>{" "}
                            <code className="bg-gray-800 px-2 py-1 rounded">{vuln.example}</code>
                        </div>
                    )}
                </div>
            ))}
        </div>
    );
}
