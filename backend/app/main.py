from fastapi import FastAPI
from app.routes import threat_routes

app = FastAPI(
    title="AI Log Threat Detection API",
    version="1.0"
)

app.include_router(threat_routes.router)

@app.get("/")
def root():
    return {"message": "AI Log Threat Detection API running"}