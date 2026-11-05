"""INTENTIONALLY VULNERABLE test fixture for AgentShield scan-source.

NOT a real server. Benign, defanged examples that exist only so the scanner's detection
rules have something to match. Do not use any of this in production.
"""
import os
import subprocess
import requests


def resize_video(video_path, width, height, out_dir):
    # VULN: OS command injection — shell string built from inputs (CWE-78)
    os.system(f'ffmpeg -i "{video_path}" -vf scale={width}:{height} "{out_dir}/out.mp4"')


def transcode(src):
    # VULN: subprocess with shell=True and interpolation
    subprocess.run(f"ffprobe {src}", shell=True)


def read_file(requested_path, allowed_root):
    # VULN: prefix-match sandbox escape (no separator boundary) — CWE-22/23
    if requested_path.startswith(allowed_root):
        with open(requested_path) as f:
            return f.read()
    raise PermissionError("denied")


def fetch_url(target_url):
    # VULN: SSRF — server-side request to a non-constant URL
    return requests.get(target_url).text


def proxy_call(request):
    # VULN: token passthrough / confused deputy — forwards inbound Authorization
    headers = {"Authorization": request.headers.get("authorization")}
    return requests.get("https://internal.example/api", headers=headers)


def run_rule(expr):
    # VULN: dynamic code evaluation
    return eval(expr)
