from flask import Flask, request, jsonify
import subprocess
import json
import re

app = Flask(__name__)


def strip_ansi(text: str) -> str:
    clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-9;?]*[ -/]*[@-~])', '', text)
    clean = re.sub(r'[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]', '', clean)
    return ' '.join(clean.split())

WPSCAN_API_TOKEN = "YOUR_TOKEN_HERE"  # optionnel - remplacer si disponible
OLLAMA_MODEL = "qwen2:0.5b"
OLLAMA_TIMEOUT = 300


def run_command(cmd, timeout_sec):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
            encoding='utf-8',
            errors='replace',
        )
        return result
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception as e:
        return str(e)


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
    return "<h1>WPScan API is running</h1>"


@app.route("/wpscan", methods=["GET", "POST"])
def wpscan_scan():
    target = request.args.get("url") or request.form.get("url")
    if not target:
        return jsonify({"error": "No target URL provided"}), 400

    # Utilise wpscan directement (installé sur Kali Linux)
    cmd = [
        "wpscan",
        "--url", target,
        "--format", "json",
        "--no-update",
        "--disable-tls-checks",
        "--max-scan-duration", "240",  # limite le scan à 4 minutes max
        "--request-timeout", "15",     # timeout par requête HTTP
        "--connect-timeout", "10",     # timeout connexion
        "-t", "5",                     # 5 threads
        "-e", "p",
    ]

    if WPSCAN_API_TOKEN != "YOUR_TOKEN_HERE":
        cmd.extend(["--api-token", WPSCAN_API_TOKEN])

    res = run_command(cmd, 300)  # 5 minutes max côté Python

    if res == "timeout":
        return jsonify({"status": "error", "message": "WPScan timed out"}), 504
    if isinstance(res, str):
        return jsonify({"status": "error", "message": res}), 500

    try:
        data = json.loads(res.stdout)

        # Résumé structuré des résultats pour l'analyse IA
        summary_lines = [f"Target: {target}"]
        if data.get("version"):
            summary_lines.append(f"WordPress version: {data['version'].get('number', 'unknown')}")
        for f in data.get("interesting_findings", []):
            summary_lines.append(f"Finding: {f.get('to_s', '')}")
        theme = data.get("main_theme", {})
        if theme:
            summary_lines.append(f"Theme: {theme.get('slug', '')} outdated={theme.get('outdated', False)}")
        for slug, p in data.get("plugins", {}).items():
            ver = p.get("version", {}).get("number", "?")
            outdated = p.get("outdated", False)
            vulns = len(p.get("vulnerabilities", []))
            summary_lines.append(f"Plugin: {slug} v{ver} outdated={outdated} vulnerabilities={vulns}")

        summary = "\n".join(summary_lines)
        analysis = analyze_with_ollama("WPScan", target, summary)

        return jsonify({
            "target": target,
            "tool": "wpscan",
            "data": data,
            "ollama_analysis": analysis,
        })
    except Exception:
        analysis = analyze_with_ollama("WPScan", target, res.stdout[:3000])
        return jsonify({
            "target": target,
            "tool": "wpscan",
            "raw_output": res.stdout,
            "ollama_analysis": analysis,
        })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, use_reloader=False)
