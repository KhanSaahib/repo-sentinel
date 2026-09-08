"""Allow ``python -m repo_sentinel``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
