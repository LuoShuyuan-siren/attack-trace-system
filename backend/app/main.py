from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router

app = FastAPI(
    title="Attack Trace System",
    description="基于主机日志、主机行为和网络流量的恶意攻击行为溯源分析系统",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    api_router,
    prefix="/api/v1",
)

@app.get("/")
def root() -> dict[str, str]:
    """系统根接口"""

    return {
        "message": "Attack Trace System API",
        "status": "running",
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    """服务健康检查接口"""

    return {
        "status": "ok",
    }