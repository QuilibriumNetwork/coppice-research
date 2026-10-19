"""Run all research tests without touching production crates or dependencies."""
from pathlib import Path
import sys
import unittest

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2 if "--verbose" in sys.argv else 1).run(suite)
    raise SystemExit(not result.wasSuccessful())
