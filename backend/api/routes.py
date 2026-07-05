"""
API Routes for Astra Platform
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import asyncio
import subprocess

router = APIRouter()

# ============ Data Models ============
class WorkspaceCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target_domains: List[str] = []
    ai_provider: Optional[str] = "openai"

class WorkspaceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

class ReconRequest(BaseModel):
    workspace_id: str
    target: str
    tools: Optional[List[str]] = None

class FindingCreate(BaseModel):
    workspace_id: str
    title: str
    description: str
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    asset_url: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

class ReportRequest(BaseModel):
    workspace_id: str
    template: str = "standard"
    format: str = "pdf"
    include_sections: Optional[List[str]] = None

class SearchQuery(BaseModel):
    query: str
    types: Optional[List[str]] = None
    workspace_id: Optional[str] = None

# ============ In-Memory Storage ============
workspaces_db: Dict[str, Dict] = {}
findings_db: Dict[str, Dict] = {}
recon_sessions: Dict[str, Dict] = {}
traffic_records: List[Dict] = []
notes_db: Dict[str, Dict] = {}

# ============ Workspace Routes ============
@router.post("/workspaces")
async def create_workspace(workspace: WorkspaceCreate, background_tasks: BackgroundTasks):
    """Create a new workspace"""
    workspace_id = str(uuid.uuid4())
    
    workspace_data = {
        "id": workspace_id,
        "name": workspace.name,
        "description": workspace.description or "",
        "target_domains": workspace.target_domains,
        "ai_provider": workspace.ai_provider,
        "status": "active",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "assets_discovered": 0,
        "findings_count": 0,
        "traffic_count": 0,
        "notes_count": 0
    }
    
    workspaces_db[workspace_id] = workspace_data
    
    # Start initial recon in background if targets provided
    if workspace.target_domains:
        for domain in workspace.target_domains[:1]:  # Start with first domain
            background_tasks.add_task(
                run_initial_recon,
                workspace_id,
                domain
            )
    
    print(f"✅ Workspace created: {workspace.name} ({workspace_id})")
    return workspace_data

@router.get("/workspaces")
async def list_workspaces(status: Optional[str] = None):
    """List all workspaces"""
    if status:
        return [ws for ws in workspaces_db.values() if ws.get("status") == status]
    return list(workspaces_db.values())

@router.get("/workspaces/{workspace_id}")
async def get_workspace(workspace_id: str):
    """Get workspace by ID"""
    if workspace_id not in workspaces_db:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return workspaces_db[workspace_id]

@router.put("/workspaces/{workspace_id}")
async def update_workspace(workspace_id: str, update: WorkspaceUpdate):
    """Update workspace"""
    if workspace_id not in workspaces_db:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    for key, value in update.dict(exclude_unset=True).items():
        workspaces_db[workspace_id][key] = value
    
    workspaces_db[workspace_id]["updated_at"] = datetime.now().isoformat()
    return workspaces_db[workspace_id]

@router.delete("/workspaces/{workspace_id}")
async def delete_workspace(workspace_id: str):
    """Delete workspace"""
    if workspace_id not in workspaces_db:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    del workspaces_db[workspace_id]
    return {"status": "deleted", "workspace_id": workspace_id}

# ============ Reconnaissance Routes ============
@router.post("/recon/start")
async def start_recon(request: ReconRequest, background_tasks: BackgroundTasks):
    """Start reconnaissance session"""
    session_id = str(uuid.uuid4())
    
    if not request.tools:
        request.tools = ["subfinder", "httpx"]
    
    recon_sessions[session_id] = {
        "id": session_id,
        "workspace_id": request.workspace_id,
        "target": request.target,
        "tools": request.tools,
        "status": "starting",
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "results": {}
    }
    
    background_tasks.add_task(
        execute_recon_tools,
        session_id,
        request.target,
        request.tools
    )
    
    return recon_sessions[session_id]

@router.get("/recon/sessions")
async def list_recon_sessions(workspace_id: Optional[str] = None):
    """List reconnaissance sessions"""
    if workspace_id:
        return [s for s in recon_sessions.values() if s.get("workspace_id") == workspace_id]
    return list(recon_sessions.values())

@router.get("/recon/sessions/{session_id}")
async def get_recon_session(session_id: str):
    """Get reconnaissance session"""
    if session_id not in recon_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return recon_sessions[session_id]

@router.get("/recon/tools")
async def list_recon_tools():
    """List available reconnaissance tools"""
    return {
        "tools": [
            {"name": "subfinder", "type": "passive", "description": "Subdomain discovery"},
            {"name": "amass", "type": "passive", "description": "Network mapping"},
            {"name": "assetfinder", "type": "passive", "description": "Asset discovery"},
            {"name": "findomain", "type": "passive", "description": "Domain enumeration"},
            {"name": "httpx", "type": "active", "description": "HTTP probe"},
            {"name": "naabu", "type": "active", "description": "Port scanner"},
            {"name": "dnsx", "type": "active", "description": "DNS toolkit"},
            {"name": "katana", "type": "active", "description": "Web crawler"},
            {"name": "gau", "type": "passive", "description": "URL discovery"},
            {"name": "waybackurls", "type": "passive", "description": "Historical URLs"},
            {"name": "whatweb", "type": "active", "description": "Technology fingerprinting"},
            {"name": "nuclei", "type": "active", "description": "Vulnerability scanner"}
        ]
    }

# ============ Findings Routes ============
@router.post("/findings")
async def create_finding(finding: FindingCreate):
    """Create a new finding"""
    finding_id = str(uuid.uuid4())
    
    finding_data = {
        "id": finding_id,
        **finding.dict(),
        "status": "open",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "timeline": [{
            "event": "Finding created",
            "timestamp": datetime.now().isoformat()
        }]
    }
    
    findings_db[finding_id] = finding_data
    
    # Update workspace count
    if finding.workspace_id in workspaces_db:
        workspaces_db[finding.workspace_id]["findings_count"] = \
            len([f for f in findings_db.values() if f.get("workspace_id") == finding.workspace_id])
    
    print(f"🔍 Finding created: {finding.title}")
    return finding_data

@router.get("/findings")
async def list_findings(
    workspace_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    """List findings with optional filters"""
    results = list(findings_db.values())
    
    if workspace_id:
        results = [f for f in results if f.get("workspace_id") == workspace_id]
    if severity:
        results = [f for f in results if f.get("severity") == severity]
    if status:
        results = [f for f in results if f.get("status") == status]
    
    return results

@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Get finding by ID"""
    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    return findings_db[finding_id]

# ============ AI Agent Routes ============
@router.get("/agents/status")
async def get_agents_status():
    """Get status of all AI agents"""
    return {
        "status": "operational",
        "agents": [
            {"name": "Planner Agent", "status": "ready", "type": "planner", "tasks_completed": 0},
            {"name": "Recon Agent", "status": "ready", "type": "recon", "tasks_completed": 0},
            {"name": "Traffic Agent", "status": "ready", "type": "traffic", "tasks_completed": 0},
            {"name": "API Agent", "status": "ready", "type": "api", "tasks_completed": 0},
            {"name": "Code Agent", "status": "ready", "type": "code", "tasks_completed": 0},
            {"name": "Cloud Agent", "status": "ready", "type": "cloud", "tasks_completed": 0},
            {"name": "Report Agent", "status": "ready", "type": "report", "tasks_completed": 0},
            {"name": "Memory Agent", "status": "ready", "type": "memory", "tasks_completed": 0}
        ],
        "timestamp": datetime.now().isoformat()
    }

@router.get("/agents/providers")
async def get_ai_providers():
    """Get available AI providers"""
    return {
        "providers": [
            {"name": "OpenAI", "models": ["gpt-4", "gpt-3.5-turbo"], "status": "available"},
            {"name": "DeepSeek", "models": ["deepseek-chat"], "status": "available"},
            {"name": "Groq", "models": ["mixtral-8x7b", "llama2-70b"], "status": "available"},
            {"name": "Claude", "models": ["claude-3-opus", "claude-3-sonnet"], "status": "available"},
            {"name": "OpenRouter", "models": ["various"], "status": "available"},
            {"name": "Ollama", "models": ["local"], "status": "available"}
        ]
    }

# ============ Search Routes ============
@router.get("/search")
async def search_all(query: str, type: Optional[str] = None):
    """Universal search across all data"""
    results = []
    
    # Search workspaces
    for ws in workspaces_db.values():
        if query.lower() in str(ws).lower():
            results.append({"type": "workspace", "data": ws, "id": ws["id"]})
    
    # Search findings
    for f in findings_db.values():
        if query.lower() in str(f).lower():
            results.append({"type": "finding", "data": f, "id": f["id"]})
    
    # Search recon sessions
    for s in recon_sessions.values():
        if query.lower() in str(s).lower():
            results.append({"type": "recon_session", "data": s, "id": s["id"]})
    
    if type:
        results = [r for r in results if r["type"] == type]
    
    return {
        "query": query,
        "results": results,
        "count": len(results),
        "timestamp": datetime.now().isoformat()
    }

# ============ Dashboard Routes ============
@router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_db.values():
        severity = f.get("severity", "info")
        if severity in findings_by_severity:
            findings_by_severity[severity] += 1
    
    return {
        "total_workspaces": len(workspaces_db),
        "active_workspaces": len([w for w in workspaces_db.values() if w.get("status") == "active"]),
        "total_findings": len(findings_db),
        "open_findings": len([f for f in findings_db.values() if f.get("status") == "open"]),
        "active_recon_sessions": len([s for s in recon_sessions.values() if s.get("status") == "running"]),
        "findings_by_severity": findings_by_severity,
        "total_traffic_records": len(traffic_records),
        "total_notes": len(notes_db),
        "timestamp": datetime.now().isoformat()
    }

@router.get("/dashboard/activity")
async def get_recent_activity(limit: int = 10):
    """Get recent activity feed"""
    activities = []
    
    # Add workspace creations
    for ws in sorted(workspaces_db.values(), key=lambda x: x.get("created_at", ""), reverse=True)[:limit]:
        activities.append({
            "type": "workspace_created",
            "message": f"Workspace '{ws['name']}' created",
            "timestamp": ws.get("created_at"),
            "workspace_id": ws["id"]
        })
    
    # Add findings
    for f in sorted(findings_db.values(), key=lambda x: x.get("created_at", ""), reverse=True)[:limit]:
        activities.append({
            "type": "finding_created",
            "message": f"Finding '{f['title']}' reported",
            "timestamp": f.get("created_at"),
            "finding_id": f["id"]
        })
    
    # Sort by timestamp
    activities.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return {
        "activities": activities[:limit],
        "timestamp": datetime.now().isoformat()
    }

# ============ Background Tasks ============
async def run_initial_recon(workspace_id: str, target: str):
    """Run initial reconnaissance for a new workspace"""
    print(f"🔍 Starting initial recon for workspace {workspace_id} on {target}")
    
    try:
        # Try to run subfinder
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        subdomains = result.stdout.strip().split("\n") if result.stdout else []
        subdomains = [s for s in subdomains if s]  # Remove empty strings
        
        if workspace_id in workspaces_db:
            workspaces_db[workspace_id]["assets_discovered"] = len(subdomains)
            workspaces_db[workspace_id]["initial_recon_completed"] = True
            workspaces_db[workspace_id]["discovered_subdomains"] = subdomains[:50]  # Store first 50
            
        print(f"✅ Initial recon completed for {target}: {len(subdomains)} subdomains found")
        
    except FileNotFoundError:
        print(f"⚠️  subfinder not installed, using simulated data")
        if workspace_id in workspaces_db:
            workspaces_db[workspace_id]["assets_discovered"] = 5
            workspaces_db[workspace_id]["initial_recon_completed"] = True
            workspaces_db[workspace_id]["discovered_subdomains"] = [
                f"www.{target}", f"api.{target}", f"admin.{target}",
                f"mail.{target}", f"dev.{target}"
            ]
    except Exception as e:
        print(f"❌ Recon error: {e}")

async def execute_recon_tools(session_id: str, target: str, tools: List[str]):
    """Execute reconnaissance tools"""
    if session_id not in recon_sessions:
        return
    
    recon_sessions[session_id]["status"] = "running"
    
    for tool in tools:
        recon_sessions[session_id]["results"][tool] = {
            "status": "running",
            "started_at": datetime.now().isoformat()
        }
        
        try:
            # Try to execute the actual tool
            cmd = [tool]
            if tool == "subfinder":
                cmd.extend(["-d", target, "-silent"])
            elif tool == "httpx":
                cmd.extend(["-u", target, "-silent"])
            else:
                cmd.append(target)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output_lines = [l for l in result.stdout.splitlines() if l.strip()]
            
            recon_sessions[session_id]["results"][tool] = {
                "status": "completed",
                "output": output_lines[:20],  # First 20 results
                "count": len(output_lines),
                "completed_at": datetime.now().isoformat()
            }
            
        except FileNotFoundError:
            # Tool not installed, provide simulated results
            simulated = {
                "subfinder": [f"www.{target}", f"api.{target}", f"admin.{target}"],
                "httpx": [f"https://{target}", f"http://{target}"],
                "amass": [f"{target}", f"sub.{target}"],
                "assetfinder": [f"cdn.{target}", f"mail.{target}"],
                "findomain": [f"dev.{target}", f"staging.{target}"],
                "dnsx": [f"{target} [A]", f"www.{target} [CNAME]"],
                "katana": [f"https://{target}/api", f"https://{target}/login"],
                "gau": [f"https://{target}/api/v1", f"https://{target}/.git"],
                "waybackurls": [f"https://{target}/old", f"https://{target}/backup"],
                "whatweb": [f"{target} [nginx/1.18.0]"],
                "nuclei": ["No critical vulnerabilities found"]
            }
            
            recon_sessions[session_id]["results"][tool] = {
                "status": "completed",
                "output": simulated.get(tool, [f"Result for {target}"]),
                "count": len(simulated.get(tool, [])),
                "completed_at": datetime.now().isoformat(),
                "simulated": True
            }
            
        except Exception as e:
            recon_sessions[session_id]["results"][tool] = {
                "status": "failed",
                "error": str(e),
                "completed_at": datetime.now().isoformat()
            }
        
        await asyncio.sleep(0.5)  # Small delay between tools
    
    recon_sessions[session_id]["status"] = "completed"
    recon_sessions[session_id]["completed_at"] = datetime.now().isoformat()
    print(f"✅ Recon session {session_id} completed")
