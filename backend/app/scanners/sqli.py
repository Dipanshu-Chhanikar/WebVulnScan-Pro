import subprocess

def run_sqlmap(target_url: str) -> str:
    try:
        command = [
            "sqlmap",
            "-u", target_url,
            "--batch",           # non-interactive
            "--level=2",
            "--risk=2"
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        return result.stdout
    except Exception as e:
        return f"SQLMap error: {str(e)}"
