import eventlet
eventlet.monkey_patch()

import os, json, re
import requests
from pathlib import Path

PROVIDERS = ["groq","anthropic","deepseek","openai","gemini","ollama"]

def _load_keys():
    """Load keys from shell rc files if not in environment"""
    for rc in ["~/.zshrc","~/.bashrc","~/.profile"]:
        p = Path(rc).expanduser()
        if not p.exists(): continue
        txt = p.read_text()
        for line in txt.splitlines():
            m = re.match(r'export\s+(\w+)=["\']?([^"\']+)["\']?', line.strip())
            if m:
                key, val = m.group(1), m.group(2).strip()
                if key not in os.environ and val:
                    os.environ[key] = val

_load_keys()

def _groq(prompt, system="", stream_cb=None):
    key = os.environ.get("GROQ_API_KEY","")
    if not key: return None
    hdrs = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    body = {
        "model": "llama-3.3-70b-versatile",
        "max_tokens": 4096,
        "stream": bool(stream_cb),
        "messages": [
            {"role":"system","content": system or "You are Astra, an elite AI security research assistant specializing in bug bounty hunting and penetration testing. Be precise, technical, and actionable."},
            {"role":"user","content": prompt}
        ]
    }
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=hdrs, json=body,
            stream=bool(stream_cb), timeout=30
        )
        if r.status_code != 200:
            print(f"[brain] Groq error {r.status_code}: {r.text[:200]}")
            return None
        if stream_cb:
            full = ""
            for line in r.iter_lines():
                if not line: continue
                if isinstance(line, bytes): line = line.decode()
                if not line.startswith("data: "): continue
                raw = line[6:]
                if raw == "[DONE]": break
                try:
                    d = json.loads(raw)
                    chunk = d["choices"][0]["delta"].get("content","")
                    if chunk:
                        full += chunk
                        stream_cb(chunk)
                except: pass
            return full or None
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except requests.exceptions.Timeout:
        print("[brain] Groq timeout")
        return None
    except Exception as e:
        print(f"[brain] Groq exception: {e}")
        return None

def _anthropic(prompt, system="", stream_cb=None):
    key = os.environ.get("ANTHROPIC_API_KEY","")
    if not key: return None
    hdrs = {"x-api-key": key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
    body = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 4096,
        "stream": bool(stream_cb),
        "system": system or "You are Astra, an elite AI security research assistant.",
        "messages": [{"role":"user","content": prompt}]
    }
    try:
        r = requests.post("https://api.anthropic.com/v1/messages",
            headers=hdrs, json=body, stream=bool(stream_cb), timeout=30)
        if r.status_code != 200: return None
        if stream_cb:
            full = ""
            for line in r.iter_lines():
                if not line: continue
                if isinstance(line, bytes): line = line.decode()
                if not line.startswith("data: "): continue
                try:
                    d = json.loads(line[6:])
                    if d.get("type") == "content_block_delta":
                        chunk = d.get("delta",{}).get("text","")
                        if chunk: full += chunk; stream_cb(chunk)
                except: pass
            return full or None
        return r.json().get("content",[{}])[0].get("text","")
    except Exception as e:
        print(f"[brain] Anthropic exception: {e}")
        return None

def _deepseek(prompt, system="", stream_cb=None):
    key = os.environ.get("DEEPSEEK_API_KEY","")
    if not key: return None
    hdrs = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    body = {"model":"deepseek-chat","max_tokens":4096,"stream":bool(stream_cb),
            "messages":[{"role":"system","content":system or "You are Astra, an elite security assistant."},
                        {"role":"user","content":prompt}]}
    try:
        r = requests.post("https://api.deepseek.com/v1/chat/completions",
            headers=hdrs, json=body, stream=bool(stream_cb), timeout=30)
        if r.status_code != 200: return None
        if stream_cb:
            full=""
            for line in r.iter_lines():
                if not line: continue
                if isinstance(line,bytes): line=line.decode()
                if not line.startswith("data: "): continue
                raw=line[6:]
                if raw=="[DONE]": break
                try:
                    d=json.loads(raw)
                    chunk=d["choices"][0]["delta"].get("content","")
                    if chunk: full+=chunk; stream_cb(chunk)
                except: pass
            return full or None
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[brain] DeepSeek exception: {e}"); return None

def _openai(prompt, system="", stream_cb=None):
    key = os.environ.get("OPENAI_API_KEY","")
    if not key: return None
    hdrs = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    body = {"model":"gpt-4o","max_tokens":4096,"stream":bool(stream_cb),
            "messages":[{"role":"system","content":system or "You are Astra, an elite security assistant."},
                        {"role":"user","content":prompt}]}
    try:
        r = requests.post("https://api.openai.com/v1/chat/completions",
            headers=hdrs, json=body, stream=bool(stream_cb), timeout=30)
        if r.status_code != 200: return None
        if stream_cb:
            full=""
            for line in r.iter_lines():
                if not line: continue
                if isinstance(line,bytes): line=line.decode()
                if not line.startswith("data: "): continue
                raw=line[6:]
                if raw=="[DONE]": break
                try:
                    d=json.loads(raw)
                    chunk=d["choices"][0]["delta"].get("content","")
                    if chunk: full+=chunk; stream_cb(chunk)
                except: pass
            return full or None
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[brain] OpenAI exception: {e}"); return None

def _gemini(prompt, system="", stream_cb=None):
    key = os.environ.get("GEMINI_API_KEY","")
    if not key: return None
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
    body = {"contents":[{"role":"user","parts":[{"text": f"{system}\n\n{prompt}" if system else prompt}]}],
            "generationConfig":{"maxOutputTokens":4096}}
    try:
        r = requests.post(url, json=body, timeout=30)
        if r.status_code != 200: return None
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        print(f"[brain] Gemini exception: {e}"); return None

def _ollama(prompt, system="", stream_cb=None):
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        tags = r.json().get("models",[])
        if not tags: return None
        model = tags[0]["name"]
    except: return None
    body = {"model":model,"stream":bool(stream_cb),
            "messages":[{"role":"system","content":system or "You are Astra, an elite security assistant."},
                        {"role":"user","content":prompt}]}
    try:
        r = requests.post("http://localhost:11434/api/chat",
            json=body, stream=bool(stream_cb), timeout=120)
        if stream_cb:
            full=""
            for line in r.iter_lines():
                if not line: continue
                try:
                    d = json.loads(line)
                    chunk = d.get("message",{}).get("content","")
                    if chunk: full+=chunk; stream_cb(chunk)
                    if d.get("done"): break
                except: pass
            return full or None
        return r.json().get("message",{}).get("content","")
    except Exception as e:
        print(f"[brain] Ollama exception: {e}"); return None

PROVIDER_FNS = {
    "groq":      _groq,
    "anthropic": _anthropic,
    "deepseek":  _deepseek,
    "openai":    _openai,
    "gemini":    _gemini,
    "ollama":    _ollama,
}

def ask(prompt, system="", stream_cb=None):
    _load_keys()
    pref = os.environ.get("ASTRA_PROVIDER","")
    order = ([pref] + [p for p in PROVIDERS if p != pref]) if pref else PROVIDERS
    for p in order:
        fn = PROVIDER_FNS.get(p)
        if not fn: continue
        print(f"[brain] Trying provider: {p}")
        result = fn(prompt, system, stream_cb)
        if result:
            print(f"[brain] Got response from: {p}")
            return result
    return "⚠ No AI provider connected. Go to Settings tab and add a Groq key (free at console.groq.com) or run: ollama serve"

def provider_status():
    _load_keys()
    if os.environ.get("GROQ_API_KEY"):      return "groq"
    if os.environ.get("ANTHROPIC_API_KEY"): return "claude"
    if os.environ.get("DEEPSEEK_API_KEY"):  return "deepseek"
    if os.environ.get("OPENAI_API_KEY"):    return "openai"
    if os.environ.get("GEMINI_API_KEY"):    return "gemini"
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        tags = r.json().get("models",[])
        if tags: return f"ollama:{tags[0]['name']}"
    except: pass
    return "none — add key in Settings"

def list_providers():
    _load_keys()
    active = []
    checks = [
        ("GROQ_API_KEY","groq"),
        ("ANTHROPIC_API_KEY","claude"),
        ("DEEPSEEK_API_KEY","deepseek"),
        ("OPENAI_API_KEY","openai"),
        ("GEMINI_API_KEY","gemini"),
    ]
    for env, name in checks:
        if os.environ.get(env):
            active.append({"name":name,"status":"active"})
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        for t in r.json().get("models",[]):
            active.append({"name":f"ollama:{t['name']}","status":"active"})
    except: pass
    return active
