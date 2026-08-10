from flask import Flask, request, jsonify
import subprocess
from urllib.parse import urlparse
import re

app = Flask(__name__)


def strip_ansi(text: str) -> str:
    # Supprime tous les codes d'échappement ANSI/VT100
    clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-9;?]*[ -/]*[@-~])', '', text)
    # Supprime les caractères spinner Braille
    clean = re.sub(r'[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]', '', clean)
    # Nettoie les espaces superflus
    return ' '.join(clean.split())

OLLAMA_MODEL = "qwen2:0.5b"
OLLAMA_TIMEOUT = 300


def analyze_with_ollama(tool_name, target, stdout_text):
    prompt = (
        "You are a cybersecurity analyst. Analyze ONLY the data provided below. "
        "Do NOT invent errors, URLs, or findings not present in the data. "
        "Use exactly 3 sections: Risk Summary, Key Findings, Remediation Steps. "
        "Keep total response under 120 words.\n\n"
        f"Tool: {tool_name}\n"
        f"Target: {target}\n\n"
        f"Scan results:\n{stdout_text[:3000]}"
    )

    retry_prompt = (
        "Analyze ONLY this data. Do not invent information. "
        "3 bullet points: risk level, main finding, one remediation.\n\n"
        f"Tool: {tool_name} | Target: {target}\n"
        f"Data:\n{stdout_text[:1000]}"
    )

    try:
        result = subprocess.run(
            ["ollama", "run", OLLAMA_MODEL],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=OLLAMA_TIMEOUT,
            check=False,
            encoding='utf-8',
            errors='replace',
        )
        if result.returncode != 0:
            return {"status": "error", "message": strip_ansi(result.stderr) or "Ollama analysis failed"}
        return {"status": "success", "model": OLLAMA_MODEL, "analysis": result.stdout.strip()}

    except subprocess.TimeoutExpired:
        try:
            result = subprocess.run(
                ["ollama", "run", OLLAMA_MODEL],
                input=retry_prompt,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                encoding='utf-8',
                errors='replace',
            )
            if result.returncode != 0:
                return {"status": "error", "message": strip_ansi(result.stderr) or "Ollama analysis failed after retry"}
            return {"status": "success", "model": OLLAMA_MODEL, "analysis": result.stdout.strip(), "retry_used": True}
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Ollama analysis timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.route("/")
def index():
    return "<h1>Nmap API is running</h1>"


@app.route("/scan", methods=["GET", "POST"])
def scan():
    url = request.args.get("url") or request.form.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    parsed = urlparse(url)
    host = parsed.netloc if parsed.netloc else parsed.path
    host = host.strip()

    if not host:
        return jsonify({"error": "Invalid host"}), 400

    cmd = [
        "nmap", "-T4", "-sV",
        "--open",
        "-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443",
        "--script", "dns-brute,http-title,banner",
        "--script-args", "dns-brute.threads=8,dns-brute.maxtime=30",
        host
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            encoding='utf-8',
            errors='replace',
        )

        # Résumé : ports ouverts + sous-domaines
        open_ports = []
        subdomains = []
        for line in result.stdout.splitlines():
            if '/tcp' in line and 'open' in line:
                open_ports.append(line.strip())
            m = re.search(r'\|\s+([\w._-]+\.' + re.escape(host) + r')\s+-', line, re.I)
            if m:
                subdomains.append(m.group(1))

        summary = (
            f"Target: {host}\n"
            f"Open ports: {', '.join(open_ports) if open_ports else 'none'}\n"
            f"Subdomains (dns-brute): {', '.join(subdomains) if subdomains else 'none'}"
        )
        analysis = analyze_with_ollama("Nmap", host, summary)

        return jsonify({
            "host": host,
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "status": "success",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "ollama_analysis": analysis,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, use_reloader=False)
