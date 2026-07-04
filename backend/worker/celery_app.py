"""
Celery application — uses Redis as broker and result backend.
"""
from __future__ import annotations
import os
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "droidraksha",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["backend.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,   # one task at a time per worker
    result_expires=3600,            # results live 1 hour in Redis
    task_routes={
        "backend.worker.tasks.run_analysis_task": {"queue": "analysis"},
    },
)
