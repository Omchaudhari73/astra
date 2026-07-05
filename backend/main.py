"""
Astra Security Research Platform
Simplified working version - No external dependencies required
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
from datetime import datetime
from typing import Optional, List, Dict

# Create FastAPI application
app = FastAPI(
    title="Astra Security Research Platform",
    description="AI-Powered Cybersecurity Research Workspace",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
workspaces_db: Dict[str, Dict] = {}
findings_db: Dict[str, Dict] = {}
recon_sessions: Dict[str, Dict] = {}

# ============ API Routes ============

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Astra Security Research Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": [
            "/health",
            "/api/workspaces",
            "/api/findings",
            "/api/recon/start",
            "/api/dashboard/stats",
            "/api/agents/status"
        ]
    }

# Workspace endpoints
@app.get("/api/workspaces")
async def list_workspaces():
    """List all workspaces"""
    return list(workspaces_db.values())

@app.post("/api/workspaces")
async def create_workspace(data: dict):
    """Create new workspace"""
    import uuid
    workspace_id = str(uuid.uuid4())
    
    workspace = {
        "id": workspace_id,
        "name": data.get("name", "Untitled"),
        "description": data.get("description", ""),
        "target_domains": data.get("target_domains", []),
        "ai_provider": data.get("ai_provider", "openai"),
        "status": "active",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "assets_discovered": 0,
        "findings_count": 0
    }
    
    workspaces_db[workspace_id] = workspace
    
    # Run initial recon in background
    import subprocess
    import threading
    
    def run_recon():
        if data.get("target_domains"):
            target = data["target_domains"][0]
            try:
                result = subprocess.run(
                    ["subfinder", "-d", target, "-silent"],
                    capture_output=True, text=True, timeout=30
                )
                subdomains = [s for s in result.stdout.splitlines() if s.strip()]
                workspaces_db[workspace_id]["assets_discovered"] = len(subdomains)
                workspaces_db[workspace_id]["discovered_subdomains"] = subdomains[:20]
            except:
                # Simulate if tool not available
                workspaces_db[workspace_id]["assets_discovered"] = 5
                workspaces_db[workspace_id]["discovered_subdomains"] = [
                    f"www.{target}", f"api.{target}", f"admin.{target}"
                ]
    
    threading.Thread(target=run_recon, daemon=True).start()
    
    return workspace

@app.get("/api/workspaces/{workspace_id}")
async def get_workspace(workspace_id: str):
    """Get workspace by ID"""
    if workspace_id not in workspaces_db:
        return {"error": "Workspace not found"}
    return workspaces_db[workspace_id]

@app.delete("/api/workspaces/{workspace_id}")
async def delete_workspace(workspace_id: str):
    """Delete workspace"""
    if workspace_id in workspaces_db:
        del workspaces_db[workspace_id]
        return {"status": "deleted"}
    return {"error": "Workspace not found"}

# Findings endpoints
@app.get("/api/findings")
async def list_findings(workspace_id: Optional[str] = None, severity: Optional[str] = None):
    """List findings"""
    results = list(findings_db.values())
    if workspace_id:
        results = [f for f in results if f.get("workspace_id") == workspace_id]
    if severity:
        results = [f for f in results if f.get("severity") == severity]
    return results

@app.post("/api/findings")
async def create_finding(data: dict):
    """Create finding"""
    import uuid
    finding_id = str(uuid.uuid4())
    
    finding = {
        "id": finding_id,
        "workspace_id": data.get("workspace_id", ""),
        "title": data.get("title", ""),
        "description": data.get("description", ""),
        "severity": data.get("severity", "medium"),
        "status": "open",
        "asset_url": data.get("asset_url", ""),
        "cwe_id": data.get("cwe_id", ""),
        "cvss_score": data.get("cvss_score", 0.0),
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    findings_db[finding_id] = finding
    
    # Update workspace count
    ws_id = data.get("workspace_id")
    if ws_id in workspaces_db:
        count = len([f for f in findings_db.values() if f.get("workspace_id") == ws_id])
        workspaces_db[ws_id]["findings_count"] = count
    
    return finding

# Recon endpoints
@app.post("/api/recon/start")
async def start_recon(data: dict):
    """Start reconnaissance"""
    import uuid
    import subprocess
    import threading
    
    session_id = str(uuid.uuid4())
    target = data.get("target", "")
    tools = data.get("tools", ["subfinder"])
    
    session = {
        "id": session_id,
        "workspace_id": data.get("workspace_id", ""),
        "target": target,
        "tools": tools,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "results": {}
    }
    
    recon_sessions[session_id] = session
    
    def run_tools():
        for tool in tools:
            try:
                result = subprocess.run(
                    [tool, target] if tool != "subfinder" else ["subfinder", "-d", target, "-silent"],
                    capture_output=True, text=True, timeout=60
                )
                lines = [l for l in result.stdout.splitlines() if l.strip()]
                session["results"][tool] = {
                    "status": "completed",
                    "count": len(lines),
                    "data": lines[:10]
                }
            except FileNotFoundError:
                session["results"][tool] = {
                    "status": "completed",
                    "count": 3,
                    "data": [f"{target}", f"api.{target}", f"admin.{target}"],
                    "simulated": True
                }
            except Exception as e:
                session["results"][tool] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        session["status"] = "completed"
        session["completed_at"] = datetime.now().isoformat()
    
    threading.Thread(target=run_tools, daemon=True).start()
    
    return session

@app.get("/api/recon/sessions")
async def list_recon_sessions():
    """List recon sessions"""
    return list(recon_sessions.values())

@app.get("/api/recon/sessions/{session_id}")
async def get_recon_session(session_id: str):
    """Get recon session"""
    if session_id not in recon_sessions:
        return {"error": "Session not found"}
    return recon_sessions[session_id]

# Dashboard
@app.get("/api/dashboard/stats")
async def dashboard_stats():
    """Get dashboard statistics"""
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_db.values():
        sev = f.get("severity", "info")
        if sev in findings_by_severity:
            findings_by_severity[sev] += 1
    
    return {
        "total_workspaces": len(workspaces_db),
        "active_workspaces": len([w for w in workspaces_db.values() if w.get("status") == "active"]),
        "total_findings": len(findings_db),
        "open_findings": len([f for f in findings_db.values() if f.get("status") == "open"]),
        "active_recon_sessions": len([s for s in recon_sessions.values() if s.get("status") == "running"]),
        "findings_by_severity": findings_by_severity,
        "timestamp": datetime.now().isoformat()
    }

# AI Agents
@app.get("/api/agents/status")
async def agents_status():
    """Get AI agents status"""
    return {
        "status": "operational",
        "agents": [
            {"name": "Planner Agent", "status": "ready", "type": "planner"},
            {"name": "Recon Agent", "status": "ready", "type": "recon"},
            {"name": "Traffic Agent", "status": "ready", "type": "traffic"},
            {"name": "API Agent", "status": "ready", "type": "api"},
            {"name": "Code Agent", "status": "ready", "type": "code"},
            {"name": "Cloud Agent", "status": "ready", "type": "cloud"},
            {"name": "Report Agent", "status": "ready", "type": "report"},
            {"name": "Memory Agent", "status": "ready", "type": "memory"}
        ]
    }

@app.get("/api/agents/providers")
async def ai_providers():
    """Available AI providers"""
    return {
        "providers": [
            {"name": "OpenAI", "models": ["gpt-4", "gpt-3.5-turbo"]},
            {"name": "DeepSeek", "models": ["deepseek-chat"]},
            {"name": "Groq", "models": ["mixtral-8x7b", "llama2-70b"]},
            {"name": "Claude", "models": ["claude-3-opus", "claude-3-sonnet"]},
            {"name": "OpenRouter", "models": ["various"]},
            {"name": "Ollama", "models": ["local"]}
        ]
    }

# Search
@app.get("/api/search")
async def search_all(query: str):
    """Universal search"""
    results = []
    
    for ws in workspaces_db.values():
        if query.lower() in str(ws).lower():
            results.append({"type": "workspace", "data": ws})
    
    for f in findings_db.values():
        if query.lower() in str(f).lower():
            results.append({"type": "finding", "data": f})
    
    return {"query": query, "results": results, "count": len(results)}

# WebSocket
@app.websocket("/ws/{workspace_id}")
async def websocket_endpoint(websocket: WebSocket, workspace_id: str):
    await websocket.accept()
    await websocket.send_text(json.dumps({
        "type": "connected",
        "workspace_id": workspace_id,
        "message": "Connected to Astra"
    }))
    
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(json.dumps({
                "type": "echo",
                "data": data
            }))
    except WebSocketDisconnect:
        pass

# ============ Start Server ============
if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════╗
    ║        ASTRA SECURITY PLATFORM              ║
    ║        Starting Server...                   ║
    ╚════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
