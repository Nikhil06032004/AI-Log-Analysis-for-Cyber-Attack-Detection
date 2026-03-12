from fastapi import APIRouter

router = APIRouter(prefix="/threats", tags=["Threats"])

@router.get("/")
def get_threats():
    return {
        "status": "success",
        "data": [
            {"ip": "192.168.1.10", "type": "BRUTE_FORCE"},
            {"ip": "10.0.0.5", "type": "SQL_INJECTION"}
        ]
    }