"""A HARDENED MCP-server fixture — the safe way to do the same operations.

AgentShield scan-source should report NO findings here.
"""
import os
import subprocess
from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"api.example.com"}


def resize_video(video_path, width, height, out_dir):
    # SAFE: argv array, no shell — metacharacters in paths are inert
    subprocess.run(
        ["ffmpeg", "-i", video_path, "-vf", f"scale={int(width)}:{int(height)}",
         os.path.join(out_dir, "out.mp4")],
        shell=False, check=True,
    )


def read_file(requested_path, allowed_root):
    # SAFE: resolve real paths and compare with a separator boundary
    root = os.path.realpath(allowed_root)
    target = os.path.realpath(requested_path)
    if target == root or target.startswith(root + os.sep):
        with open(target) as f:
            return f.read()
    raise PermissionError("denied")


def fetch_url(target_url):
    # SAFE: allowlist the host and require https before making the request
    u = urlparse(target_url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get("https://api.example.com/data", timeout=10).text
