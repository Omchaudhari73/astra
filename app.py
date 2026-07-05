import eventlet
eventlet.monkey_patch()

import os, json, threading
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO, emit

import brain, tools, memory

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)

HTML = open("index.html").read()

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/status")
def status():
    return jsonify({
        "ai_provider":   brain.provider_status(),
        "ai_providers":  brain.list_providers(),
        "tools":         tools.check_tools(),
        "memory":        memory.memory_stats(),
        "sessions":      memory.get_all_sessions(),
        "saved_targets": tools.get_saved_targets(),
        "version":       "6.0",
    })

@app.route("/api/memory")
def get_memory():
    return jsonify({"entries": memory.recall(
        query=request.args.get("q"),
        target=request.args.get("target"),
        limit=100)})

@app.route("/api/memory/clear", methods=["POST"])
def clear_memory():
    from pathlib import Path
    p = Path("memory/hunt_memory.jsonl")
    if p.exists(): p.write_text("")
    return jsonify({"ok": True})

@app.route("/api/report", methods=["POST"])
def make_report():
    d = request.json or {}
    report_md, path = tools.generate_report(
        target=d.get("target","unknown"),
        finding=d.get("finding","Vulnerability"),
        severity=d.get("severity","Medium"),
        impact=d.get("impact",""),
        steps=d.get("steps",""),
        tools_used=d.get("tools_used",""),
        vuln_type=d.get("vuln_type",""),
    )
    memory.remember("report", f"Report: {d.get('finding','')}", target=d.get("target",""))
    return jsonify({"report": report_md, "saved_to": path})

@app.route("/api/validate", methods=["POST"])
def validate():
    return jsonify(tools.validate_finding((request.json or {}).get("finding","")))

@app.route("/api/providers", methods=["POST"])
def set_provider():
    d = request.json or {}
    key_map = {"groq":"GROQ_API_KEY","anthropic":"ANTHROPIC_API_KEY",
               "deepseek":"DEEPSEEK_API_KEY","openai":"OPENAI_API_KEY","gemini":"GEMINI_API_KEY"}
    provider = d.get("provider","")
    key = d.get("key","")
    if provider in key_map and key:
        os.environ[key_map[provider]] = key
        os.environ["ASTRA_PROVIDER"] = provider
        rc = os.path.expanduser("~/.zshrc" if os.path.exists(os.path.expanduser("~/.zshrc")) else "~/.bashrc")
        with open(rc,"a") as f:
            f.write(f'\nexport {key_map[provider]}="{key}"\nexport ASTRA_PROVIDER="{provider}"\n')
        return jsonify({"ok":True,"provider":provider})
    if provider == "ollama":
        os.environ["ASTRA_PROVIDER"] = "ollama"
        return jsonify({"ok":True,"provider":"ollama"})
    return jsonify({"ok":False,"error":"Unknown provider"})

@app.route("/api/whatweb", methods=["POST"])
def whatweb():
    target = (request.json or {}).get("target","")
    return jsonify({"result": tools.whatweb_scan(target)})

@app.route("/api/scan_url", methods=["POST"])
def scan_url():
    d = request.json or {}
    return jsonify({"findings": tools.scan_single_url(d.get("url",""), d.get("headers",""))})

# ── WebSocket events ────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("status", {"msg":"Astra v6.0 ready","provider":brain.provider_status()})

@socketio.on("chat")
def on_chat(data):
    msg    = data.get("message","").strip()
    target = data.get("target","")
    system = data.get("system","")
    if not msg: return
    ctx = ""
    if target:
        c = memory.get_context_for_target(target)
        if c and "No previous" not in c:
            ctx = f"\n\n[Hunt memory for {target}]\n{c}\n\n"
    emit("thinking", {"msg":"Astra is analyzing..."})

    def run():
        def cb(chunk): socketio.emit("stream", {"chunk": chunk})
        resp = brain.ask(ctx + msg, system=system, stream_cb=cb)
        socketio.emit("stream_done", {"full": resp})
        memory.remember("chat", f"Q:{msg[:80]} A:{resp[:150]}", target=target)
    threading.Thread(target=run, daemon=True).start()

@socketio.on("recon")
def on_recon(data):
    target  = data.get("target","").strip()
    headers = data.get("headers","")
    if not target: emit("error",{"msg":"No target"}); return
    emit("recon_start",{"target":target})
    memory.start_session(target)

    def run():
        def p(msg): socketio.emit("recon_progress",{"msg":msg})
        rd = tools.recon(target, progress_cb=p)
        subs   = rd["steps"].get("subdomains",[])
        live   = rd["steps"].get("live_hosts","")
        nuclei = rd["steps"].get("nuclei","")
        urls   = rd["steps"].get("urls",[])
        techs  = rd["steps"].get("technologies",{})
        secs   = rd["steps"].get("js_secrets",[])
        nmap   = rd["steps"].get("nmap","")

        prompt = f"""Full recon complete for {target}.

STATS:
- Subdomains: {len(subs)} | Live hosts: {len(live.splitlines())} | URLs crawled: {len(urls)}
- JS secrets found: {len(secs)} | Nuclei pre-scan findings: {len([l for l in nuclei.splitlines() if l.strip()])}

TOP SUBDOMAINS: {', '.join(subs[:25])}
TECHNOLOGIES: {json.dumps(techs, indent=1)[:600]}
LIVE HOSTS (first 15): {chr(10).join(live.splitlines()[:15])}
NUCLEI PRE-SCAN: {nuclei[:600]}
NMAP: {nmap[:400]}
JS SECRETS: {json.dumps(secs[:5],indent=1)[:400]}
SAMPLE URLS (25): {chr(10).join(urls[:25])}

Provide a ELITE security researcher analysis:
1. **Attack Surface Rating** (Critical/High/Medium/Low) with justification
2. **Top 7 Priority Targets** — specific URLs/subdomains with exact attack vectors
3. **Technology Stack Analysis** — CVEs, known weaknesses for detected tech
4. **IDOR/Auth Bypass Map** — endpoints most likely vulnerable based on URL patterns
5. **Quick Wins** — findings an attacker could confirm in under 10 minutes
6. **Chain Attack Opportunities** — how findings could be combined for critical impact
7. **Unusual/Interesting** — anything that stands out as non-standard"""

        socketio.emit("ai_analysis_start",{"msg":"AI performing deep recon analysis..."})
        analysis = brain.ask(prompt)
        memory.remember("recon", f"Recon: {analysis[:300]}", target=target)
        socketio.emit("recon_done",{
            "data":rd,"analysis":analysis,
            "stats":{
                "subdomains":len(subs),"live_hosts":len(live.splitlines()),
                "urls":len(urls),"nuclei_findings":len([l for l in nuclei.splitlines() if l.strip()]),
                "js_secrets":len(secs),
            }
        })
    threading.Thread(target=run, daemon=True).start()

@socketio.on("hunt")
def on_hunt(data):
    target  = data.get("target","").strip()
    headers = data.get("headers","")
    if not target: emit("error",{"msg":"No target"}); return
    emit("hunt_start",{"target":target})

    def run():
        def p(msg): socketio.emit("hunt_progress",{"msg":msg})
        findings = tools.hunt(target, headers=headers, progress_cb=p)

        critical = [f for f in findings if f.get("severity","").lower()=="critical"]
        high     = [f for f in findings if f.get("severity","").lower()=="high"]
        medium   = [f for f in findings if f.get("severity","").lower()=="medium"]

        prompt = f"""Ultra-scan complete for {target}.

FINDINGS SUMMARY:
- CRITICAL: {len(critical)} | HIGH: {len(high)} | MEDIUM: {len(medium)} | TOTAL: {len(findings)}

CRITICAL FINDINGS:
{json.dumps(critical[:8], indent=2)[:2000]}

HIGH FINDINGS:
{json.dumps(high[:8], indent=2)[:1500]}

As an elite bug bounty hunter, provide:
1. **Triage** — which findings are definitely real vs need manual verification
2. **Severity Assessment** — agreed/disagreed severities with CVSS justification
3. **Manual Confirmation Steps** — exact HTTP requests/Burp steps for top 3 findings
4. **Attack Chain** — how to combine these for maximum impact (escalation path)
5. **Estimated Bounty** — realistic payout range for each confirmed finding
6. **Report Priority** — which to report first and why
7. **Missed Tests** — 5 manual tests the scanner likely couldn't automate"""

        socketio.emit("ai_analysis_start",{"msg":"AI performing elite triage..."})
        analysis = brain.ask(prompt)
        memory.remember("finding", f"Hunt findings: {len(findings)}, critical: {len(critical)}", target=target)
        socketio.emit("hunt_done",{
            "findings":findings,"analysis":analysis,
            "count":len(findings),
            "stats":{"critical":len(critical),"high":len(high),"medium":len(medium)}
        })
    threading.Thread(target=run, daemon=True).start()

@socketio.on("autopilot")
def on_autopilot(data):
    target = data.get("target","").strip()
    if not target: emit("error",{"msg":"No target"}); return
    emit("autopilot_start",{"target":target})
    memory.start_session(target)

    def run():
        def p(msg): socketio.emit("autopilot_progress",{"msg":msg})
        p(f"[autopilot] Phase 1: Recon on {target}...")
        rd = tools.recon(target, progress_cb=p)
        p("[autopilot] Phase 2: Ultra-scan 25 vulnerability classes...")
        findings = tools.hunt(target, progress_cb=p)
        p("[autopilot] Phase 3: AI executive analysis...")

        subs = rd["steps"].get("subdomains",[])
        urls = rd["steps"].get("urls",[])
        critical = [f for f in findings if f.get("severity","").lower()=="critical"]
        high = [f for f in findings if f.get("severity","").lower()=="high"]

        prompt = f"""AUTOPILOT COMPLETE for {target}

Total findings: {len(findings)} (Critical: {len(critical)}, High: {len(high)})
Subdomains: {len(subs)} | URLs: {len(urls)}

TOP CRITICAL:
{json.dumps(critical[:6],indent=2)[:2000]}

TOP HIGH:
{json.dumps(high[:5],indent=2)[:1500]}

Write a COMPLETE executive bug bounty report:
1. **Overall Risk Rating** with justification
2. **Attack Narrative** — tell the story of how an attacker would exploit this
3. **Critical Findings** — detailed write-up of each critical finding
4. **High Findings** — summary of each high finding
5. **Attack Chain** — step-by-step escalation from entry to full compromise
6. **Business Impact** — explain impact in business/executive language
7. **Total Estimated Bounty** — breakdown by finding with realistic ranges
8. **Immediate Actions** — what the team should patch first"""

        analysis = brain.ask(prompt)
        memory.remember("autopilot", f"Autopilot complete: {len(findings)} findings", target=target)
        socketio.emit("autopilot_done",{
            "recon":rd,"findings":findings,"analysis":analysis,
            "stats":{"subdomains":len(subs),"urls":len(urls),
                    "findings":len(findings),"critical":len(critical),"high":len(high)}
        })
    threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    print("""
 █████╗ ███████╗████████╗██████╗  █████╗ 
██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
███████║███████╗   ██║   ██████╔╝███████║
██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║
██║  ██║███████║   ██║   ██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
        v6.0 — Ultra Scanner
  Web UI → http://localhost:5000
""")
    memory.init()
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
