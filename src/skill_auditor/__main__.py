"""Entry point: python -m skill_auditor <skill path>"""

import sys

from skill_auditor.cli import main

if __name__ == "__main__":
    sys.exit(main())
