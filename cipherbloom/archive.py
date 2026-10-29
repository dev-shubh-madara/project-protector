"""Safely get a project onto disk: a folder, a .zip file or a public repo link.

CipherBloom NEVER executes the code it receives. It only reads text files.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile

MAX_FILES = 20000
MAX_TOTAL = 500 * 1024 * 1024
ALLOWED_HOSTS = re.compile(r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[\w.\-]+/[\w.\-]+(\.git)?/?$")


class SourceError(Exception):
    pass


def extract_zip(zip_path):
    dest = tempfile.mkdtemp(prefix="cipherbloom-")
    base = os.path.realpath(dest)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_TOTAL:
                raise SourceError("Zip is too large to scan safely.")
            for info in infos:
                target = os.path.realpath(os.path.join(dest, info.filename))
                if not (target == base or target.startswith(base + os.sep)):
                    raise SourceError("Zip contains an unsafe path: %s" % info.filename)
            zf.extractall(dest)
    except zipfile.BadZipFile:
        shutil.rmtree(dest, ignore_errors=True)
        raise SourceError("That file is not a valid zip.")
    except SourceError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    entries = os.listdir(dest)
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        return os.path.join(dest, entries[0]), dest
    return dest, dest


def clone_repo(url):
    if not ALLOWED_HOSTS.match(url):
        raise SourceError("Only public https links from github.com, gitlab.com or bitbucket.org are accepted.")
    if not shutil.which("git"):
        raise SourceError("git is not installed, so the repo cannot be downloaded. Download the zip instead.")
    dest = tempfile.mkdtemp(prefix="cipherbloom-")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        res = subprocess.run(
            ["git", "clone", "--depth", "50", "--no-tags", "--", url, os.path.join(dest, "repo")],
            capture_output=True, text=True, timeout=180, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise SourceError("Could not download the repo: %s" % exc)
    if res.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise SourceError("Could not download the repo (is it public?): %s" % res.stderr.strip()[:200])
    return os.path.join(dest, "repo"), dest


def prepare(source):
    """Return (scan_root, cleanup_dir_or_None)."""
    if source.startswith("https://") or source.startswith("http://"):
        root, tmp = clone_repo(source)
        return root, tmp
    if os.path.isdir(source):
        return os.path.abspath(source), None
    if os.path.isfile(source) and source.lower().endswith(".zip"):
        root, tmp = extract_zip(source)
        return root, tmp
    raise SourceError("'%s' is not a folder, a .zip file or a repo link." % source)
