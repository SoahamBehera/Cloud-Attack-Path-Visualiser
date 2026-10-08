"""Streamlit dashboard entrypoint.

Forwards directly to the main app.py dashboard implementation.
"""

from pathlib import Path
import runpy
import sys

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

_target = Path(__file__).resolve().parent.parent / "app.py"
runpy.run_path(str(_target), run_name="__main__")
