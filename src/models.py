import json
import os

try:
    from . import globals
    from .utils import debug_print
except ImportError:
    import globals
    from utils import debug_print

def get_models():
    try:
        with open(globals.MODELS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_models(models):
    try:
        tmp_path = f"{globals.MODELS_FILE}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(models, f, indent=2)
        os.replace(tmp_path, globals.MODELS_FILE)
    except Exception as e:
        debug_print(f"❌ Error saving models: {e}")
