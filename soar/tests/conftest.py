import os
import sys
from pathlib import Path

# Ensure the source package is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Ensure env vars are set before any soar module import
os.environ.setdefault("ABUSEIPDB_API_KEY", "test_key")
os.environ.setdefault("OPNSENSE_API_URL", "https://opnsense.test/api")
os.environ.setdefault("OPNSENSE_API_KEY", "test_opn_key")
os.environ.setdefault("OPNSENSE_API_SECRET", "test_opn_secret")
os.environ.setdefault("LOG_LEVEL", "DEBUG")
