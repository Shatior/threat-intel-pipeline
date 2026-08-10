"""Permite ejecutar el paquete con ``python -m threatintel``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
