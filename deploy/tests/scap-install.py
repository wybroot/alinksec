#!/usr/bin/env python3
"""CI uses the same explicit, pinned runtime installer as operators."""
from pathlib import Path
import runpy
runpy.run_path(str(Path(__file__).resolve().parents[1]/'baseline'/'scap'/'install-runtime.py'), run_name='__main__')
