from flask import Flask, request, jsonify
import subprocess
from urllib.parse import urlparse
import json
import re

NUCLEI_TEMPLATES = "/home/kali/.local/nuclei-templates/"

app = Flask(__name__)


def strip_ansi(text: str) -> str:
    clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-9;?]*[ -/]*[@-~])', '', text)
    clean = re.sub(r'[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]', '', clean)
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
    return "<h1>Nuclei API is running</h1>"


@app.route("/scan", methods=["GET", "POST"])
def nuclei_scan():
    target = request.args.get("url") or request.form.get("url")
    if not target:
        return jsonify({"error": "No target URL provided"}), 400

    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"

    # Templates ciblés (CVEs exclus — 4001 templates trop lents)
    focused = [
        NUCLEI_TEMPLATES + "http/misconfiguration",
        NUCLEI_TEMPLATES + "http/exposed-panels",
        NUCLEI_TEMPLATES + "http/technologies",
        NUCLEI_TEMPLATES + "http/vulnerabilities",
    ]
    template_args = []
    for t in focused:
        template_args += ["-t", t]

    cmd = [
        "nuclei", "-u", target,
        *template_args,
        "-severity", "critical,high,medium,low,info",
        "-silent", "-jsonl",
        "-timeout", "5",
        "-retries", "1",
        "-rl", "100",
        "-c",  "50",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
            encoding='utf-8',
            errors='replace',
        )

        findings = []
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    findings.append({"raw_output": line})

        # Résumé structuré pour l'analyse IA
        summary_lines = [f"Target: {target}", f"Findings: {len(findings)}"]
        for f in findings[:20]:  # limite à 20 pour ne pas dépasser le contexte
            if "raw_output" in f:
                summary_lines.append(f"- {f['raw_output']}")
            else:
                name     = f.get("info", {}).get("name", f.get("template-id", "unknown"))
                severity = f.get("info", {}).get("severity", "info")
                matched  = f.get("matched-at", f.get("host", ""))
                summary_lines.append(f"- [{severity.upper()}] {name} at {matched}")
        summary = "\n".join(summary_lines)
        analysis = analyze_with_ollama("Nuclei", target, summary)

        return jsonify({
            "target": target,
            "status": "success",
            "results_count": len(findings),
            "findings": findings,
            "stderr": result.stderr,
            "ollama_analysis": analysis,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "The scan took too long and was terminated."}), 504
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, use_reloader=False)
