"""Module entrypoint for `python -m foxclaw`."""

from foxclaw.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
