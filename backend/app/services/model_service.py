"""
model_service.py — Shared UpgradedAMIDES model singleton.

All route modules import get_model() from here so the model is only
loaded once regardless of how many routers are registered.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

MODEL_PATH = PROJECT_ROOT / "ml_engine" / "upgraded_amides.pkl"

_model = None
_model_load_error: str = ""


def get_model():
    """
    Load and cache the UpgradedAMIDES model.
    Raises RuntimeError if the model file is missing or fails to load.
    """
    global _model, _model_load_error
    if _model is not None:
        return _model
    if _model_load_error:
        raise RuntimeError(_model_load_error)
    try:
        from ml_engine.upgraded_amides import UpgradedAMIDES
        _model = UpgradedAMIDES.load(str(MODEL_PATH))
    except FileNotFoundError:
        _model_load_error = (
            f"Model file not found at {MODEL_PATH}. "
            "Run 'python ml_engine/train.py' to train and save the model."
        )
        raise RuntimeError(_model_load_error)
    except Exception as exc:
        _model_load_error = f"Failed to load model: {exc}"
        raise RuntimeError(_model_load_error)
    return _model


def model_status() -> dict:
    """Return a status dict about model availability."""
    model_exists = MODEL_PATH.exists()
    model_loaded = _model is not None
    if model_loaded:
        status = "ready"
    elif model_exists:
        status = "model_file_found_not_loaded"
    else:
        status = "model_not_trained"
    return {
        "status": status,
        "model_path": str(MODEL_PATH),
        "model_file_exists": model_exists,
        "model_loaded_in_memory": model_loaded,
    }
