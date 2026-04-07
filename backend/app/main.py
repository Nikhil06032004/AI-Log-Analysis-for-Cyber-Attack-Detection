from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import threat_routes
from app.routes import ingest_routes
from app.routes import system_routes
from app.routes import metrics_routes

app = FastAPI(title="AI Log Threat Detection API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(threat_routes.router)
app.include_router(ingest_routes.router)
app.include_router(system_routes.router)
app.include_router(metrics_routes.router)

@app.get("/")
def root():
    return {"message": "AI Log Threat Detection API running"}