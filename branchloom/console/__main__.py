"""``python -m branchloom.console`` — same entry point as the ``branchloom`` console script."""
import sys as loom_sys
from . import launch as launch
if __name__ == '__main__':
    loom_sys.exit(launch())
