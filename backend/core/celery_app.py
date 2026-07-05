"""
Celery configuration for background tasks
"""
from celery import Celery
from core.config import settings

celery_app = Celery(
    'astra_tasks',
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3000,  # 50 minutes soft limit
    worker_max_tasks_per_child=100,
    worker_prefetch_multiplier=1,
)

@celery_app.task(name='health_check')
def health_check():
    """Test task to verify Celery is working"""
    return {"status": "ok", "message": "Celery is working!"}

@celery_app.task(name='run_recon')
def run_recon_task(workspace_id: str, target: str, tools: list):
    """Background task for running reconnaissance"""
    import subprocess
    import json
    
    results = {}
    for tool in tools:
        try:
            result = subprocess.run(
                [tool, target],
                capture_output=True,
                text=True,
                timeout=60
            )
            results[tool] = {
                "status": "completed",
                "output_lines": len(result.stdout.splitlines()),
                "data": result.stdout[:1000]  # First 1000 chars
            }
        except Exception as e:
            results[tool] = {
                "status": "failed",
                "error": str(e)
            }
    
    return results
