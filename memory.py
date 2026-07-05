import os, json, time, re
from pathlib import Path
from datetime import datetime

MEM_DIR = Path("memory")
MEM_DIR.mkdir(exist_ok=True)
MEM_FILE = MEM_DIR / "hunt_memory.jsonl"
SESS_FILE = MEM_DIR / "sessions.jsonl"
MAX_SIZE = 10 * 1024 * 1024

def init():
    MEM_FILE.touch(exist_ok=True)
    SESS_FILE.touch(exist_ok=True)

def remember(type_, content, target=""):
    entry = {"type":type_,"content":content,"target":target,
              "timestamp":datetime.now().isoformat()}
    with open(MEM_FILE,"a") as f:
        f.write(json.dumps(entry)+"\n")
    if MEM_FILE.stat().st_size > MAX_SIZE:
        _rotate()

def _rotate():
    lines=MEM_FILE.read_text().splitlines()
    keep=lines[len(lines)//2:]
    MEM_FILE.write_text("\n".join(keep)+"\n")

def recall(query=None, target=None, limit=50):
    entries=[]
    if not MEM_FILE.exists(): return []
    for line in MEM_FILE.read_text().splitlines():
        try:
            e=json.loads(line)
            if target and e.get("target","").lower()!=target.lower(): continue
            if query and query.lower() not in e.get("content","").lower(): continue
            entries.append(e)
        except: pass
    return entries[-limit:]

def get_context_for_target(target):
    entries=recall(target=target,limit=20)
    if not entries: return "No previous memory for this target."
    return "\n".join([f"[{e['type']}] {e['content']}" for e in entries])

def start_session(target):
    entry={"target":target,"started":datetime.now().isoformat()}
    with open(SESS_FILE,"a") as f:
        f.write(json.dumps(entry)+"\n")

def get_all_sessions():
    if not SESS_FILE.exists(): return []
    sessions=[]
    for line in SESS_FILE.read_text().splitlines():
        try: sessions.append(json.loads(line))
        except: pass
    seen=set(); unique=[]
    for s in reversed(sessions):
        if s["target"] not in seen:
            seen.add(s["target"]); unique.append(s)
    return list(reversed(unique))[-10:]

def memory_stats():
    size=MEM_FILE.stat().st_size if MEM_FILE.exists() else 0
    lines=len(MEM_FILE.read_text().splitlines()) if MEM_FILE.exists() else 0
    return {"total_entries":lines,"size_mb":round(size/1024/1024,2)}
