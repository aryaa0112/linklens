"""Launch the LinkLens local dashboard."""

from __future__ import annotations

import argparse

from .web import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the privacy-first LinkLens URL risk dashboard.")
    parser.add_argument("--port", type=int, default=8765, help="Local dashboard port (default: 8765).")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    serve(args.port)


if __name__ == "__main__":
    main()
