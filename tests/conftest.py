import os
import sys
from pathlib import Path


def _norm_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path or os.getcwd()))


REPO_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT_NORM = _norm_path(str(REPO_ROOT))

if not any(_norm_path(p) == REPO_ROOT_NORM for p in sys.path):
    sys.path.insert(0, str(REPO_ROOT))
