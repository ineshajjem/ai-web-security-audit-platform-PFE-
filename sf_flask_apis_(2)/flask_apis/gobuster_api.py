# Importation des modules nécessaires
from flask import Flask, request, jsonify   # Flask pour créer l'API web
import subprocess                           # Pour exécuter des commandes système (Gobuster, Ollama)
import re                                   # Pour nettoyer les sorties avec des regex

# Initialisation de l'application Flask
app = Flask(__name__)


# Fonction utilitaire pour nettoyer les sorties (supprimer couleurs, animations, espaces)
def strip_ansi(text: str) -> str:
    # Supprime les codes ANSI (couleurs, etc.)
    clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-9;?]*[ -/]*[@-~])', '', text)
    # Supprime les caractères spinner (Braille utilisés pour animation)
    clean = re.sub(r'[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]', '', clean)
    # Supprime les espaces superflus
    return ' '.join(clean.split())

# Constantes globales
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"  # Wordlist par défaut pour Gobuster
OLLAMA_MODEL = "qwen2:0.5b"                               # Modèle IA utilisé pour l'analyse
OLLAMA_TIMEOUT = 300                                      # Timeout maximum pour Ollama


# Fonction pour exécuter une commande système (ex: Gobuster)
def run_command(cmd, timeout_sec):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,  # Capture stdout et stderr
            text=True,            # Retourne en texte (pas en bytes)
            timeout=timeout_sec,  # Timeout global
            check=False,          # Ne pas lever d'erreur si code retour ≠ 0
        )
        return result
    except subprocess.TimeoutExpired:
        return "timeout"          # Retourne "timeout" si la commande prend trop de temps
    except Exception as e:
        return str(e)              # Retourne le message d'erreur si autre problème


# Fonction qui envoie les résultats à Ollama pour analyse IA
def analyze_with_ollama(tool_name, target, stdout_text):
    # Prompt principal (réponse structurée en 3 sections)
    prompt = (
        "You are a cybersecurity analyst. Analyze ONLY the data provided below. "
        "Do NOT invent errors, URLs, or findings not present in the data. "
        "Use exactly 3 sections: Risk Summary, Key Findings, Remediation Steps. "
        "Keep total response under 120 words.\n\n"
        f"Tool: {tool_name}\n"
        f"Target: {target}\n\n"
        f"Scan results:\n{stdout_text[:3000]}"
    )

    # Prompt de secours si timeout (version simplifiée en 3 bullet points)
    retry_prompt = (
        "Analyze ONLY this data. Do not invent information. "
        "3 bullet points: risk level, main finding, one remediation.\n\n"
        f"Tool: {tool_name} | Target: {target}\n"
        f"Data:\n{stdout_text[:1000]}"
    )

    try:
        # Exécution du modèle Ollama avec le prompt principal
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
        # Si erreur → retourne un message d'erreur
        if result.returncode != 0:
            return {"status": "error", "message": strip_ansi(result.stderr) or "Ollama analysis failed"}
        # Sinon → retourne l'analyse IA
        return {"status": "success", "model": OLLAMA_MODEL, "analysis": result.stdout.strip()}

    # Si timeout → relance avec prompt simplifié
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


# Route d'accueil (test de disponibilité)
@app.route("/")
def index():
    return "<h1>Gobuster API is running</h1>"


# Route principale pour lancer un scan Gobuster
@app.route("/gobuster", methods=["GET", "POST"])
def gobuster_scan():
    # Récupère l'URL cible depuis GET ou POST
    target = request.args.get("url") or request.form.get("url")
    if not target:
        return jsonify({"error": "No target URL provided"}), 400

    wordlist = DEFAULT_WORDLIST

    # Commande Gobuster construite
    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-q",              # mode silencieux (pas de logs inutiles)
        "--no-color",      # pas de couleurs ANSI
        "-t", "50",        # 50 threads (plus rapide)
        "--timeout", "3s", # timeout par requête
    ]

    # Exécution de Gobuster avec timeout global de 600s
    res = run_command(cmd, 600)

    # Gestion des erreurs
    if res == "timeout":
        return jsonify({"status": "error", "message": "Gobuster timed out"}), 504
    if isinstance(res, str):
        return jsonify({"status": "error", "message": res}), 500

    # Extraction des chemins trouvés
    paths = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line and (line.startswith('/') or '(Status:' in line):
            paths.append(line)

    # Résumé pour l'analyse IA
    summary = f"Target: {target}\nPaths found: {len(paths)}\n" + "\n".join(paths[:30])
    analysis = analyze_with_ollama("Gobuster dir", target, summary)

    # Réponse JSON finale
    return jsonify({
        "target": target,
        "tool": "gobuster",
        "stdout": res.stdout,
        "stderr": res.stderr,
        "ollama_analysis": analysis,
    })


# Lancement du serveur Flask
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, use_reloader=False)
