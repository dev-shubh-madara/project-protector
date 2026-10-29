from __future__ import annotations

import os

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", ".mypy_cache", ".pytest_cache", "site-packages", ".idea",
    ".vscode", ".tox", "target", "vendor",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svgz", ".pdf",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".mp3", ".mp4", ".wav", ".ogg",
    ".mov", ".avi", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".exe", ".dll",
    ".so", ".dylib", ".pyc", ".class", ".jar", ".bin", ".onnx", ".pt", ".pth",
    ".safetensors", ".gguf", ".sqlite", ".db", ".map",
}
NOISY_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "composer.lock", "Cargo.lock", "go.sum",
}
MAX_BYTES = 1500000


def iter_files(root):
    """Yield text-like file paths under root, skipping vendored/binary/huge files."""
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext in BINARY_EXT or name in NOISY_NAMES or name.endswith(".min.js"):
                continue
            try:
                if os.path.islink(path) or os.path.getsize(path) > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield path


def read_text(path):
    """Return file text, or None if unreadable or binary."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def ignored_file(text):
    """True when the first lines contain the `cipherbloom:ignore-file` marker."""
    return "cipherbloom:ignore-file" in "\n".join(text.splitlines()[:5])


def rel(path, root):
    base = root if os.path.isdir(root) else os.path.dirname(root)
    return os.path.relpath(path, base or ".").replace(os.sep, "/")
