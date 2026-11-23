"""Explicit LOCAL launcher. No app import or database access at module import."""
import argparse
import os
from pathlib import Path, PureWindowsPath


def reject_public_database(database: str | Path) -> Path:
    """Keep SQLite outside the directory exposed by StaticFiles."""
    candidate = Path(database).resolve()
    public = Path(__file__).resolve().parent / "static"
    public = public.resolve()
    if candidate == public or public in candidate.parents:
        raise ValueError("A database cannot be stored in the public static directory")
    return candidate


def local_configuration(database: str, model: str) -> dict[str, str]:
    if not isinstance(database, str) or not database or "\x00" in database:
        raise ValueError("Use an absolute local .sqlite3 path")
    path = Path(database)
    if not path.is_absolute() or path.drive.startswith("\\\\") or path.suffix.lower() != ".sqlite3":
        raise ValueError("Use an absolute local .sqlite3 path")
    # Reject device names, NTFS streams and ambiguous spellings before any I/O.
    if any(part == ".." or part.rstrip(" .") != part or ":" in part
           or PureWindowsPath(part).is_reserved()
           or any(ord(char) < 32 or char in '<>"|?*' for char in part)
           for part in path.parts[1:]):
        raise ValueError("Use a regular database path without device names, streams or aliases")
    if (not isinstance(model, str) or not model.strip() or len(model) > 200
            or any(ord(char) < 32 or ord(char) == 127 for char in model)):
        raise ValueError("Specify one installed Ollama model")
    reject_public_database(path)
    return {
        "PYTHON_DOTENV_DISABLED": "1",
        "AI1_PROVIDER": "ollama",
        "AI1_MODE": "LOCAL_ONLY",
        "AI1_DATABASE_PATH": str(path),
        "OLLAMA_BASE_URL": "http://127.0.0.1:11434",
        "OLLAMA_MODEL": model.strip(),
        "AI1_API_KEY": "",
    }


def main(argv=None, *, memory_storage_factory=None) -> int:
    parser = argparse.ArgumentParser(description="AI-1 LOCAL: explicit database, no dotenv or cloud")
    parser.add_argument("--database", required=True, help="Absolute .sqlite3 history path")
    parser.add_argument("--model", default="qwen2.5:1.5b", help="Already installed Ollama model")
    parser.add_argument("--workspace", action="store_true", help="Opt in to a separate NEW workspace schema; never imports legacy history")
    parser.add_argument("--memory-v2", action="store_true", help="Opt in to the separately installed Windows authority")
    args = parser.parse_args(argv)
    if memory_storage_factory is not None and not args.workspace:
        parser.error("Trusted storage requires a local workspace")
    if args.memory_v2 and (not args.workspace or memory_storage_factory is not None):
        parser.error("Memory V2 requires the explicit LOCAL workspace launcher")
    try:
        environment = local_configuration(args.database, args.model)
        path = Path(environment["AI1_DATABASE_PATH"])
        if not path.parent.is_dir():
            raise ValueError("The selected database directory must already exist")
        for item in (path, *path.parents):
            if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
                raise ValueError("Linked database paths require separate review")
    except ValueError as error:
        parser.error(str(error))
    os.environ.update(environment)  # This process only; no Windows/user settings.
    binding = None
    if args.memory_v2:
        from app.memory_launch_v2 import make_binding
        try:
            binding = make_binding()
        except ValueError as error:
            parser.error(str(error))
    import uvicorn
    target = "app.main:create_app"
    if args.workspace:
        from functools import partial
        from app.main import create_app
        options = {"memory_service_binding": binding} if binding is not None else {}
        target = partial(create_app, workspace_path=str(path), memory_storage_factory=memory_storage_factory,
                         **options)
    uvicorn.run(target, factory=True, host="127.0.0.1", port=8000,
                workers=1, reload=False, proxy_headers=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
