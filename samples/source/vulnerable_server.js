// INTENTIONALLY VULNERABLE test fixture for AgentShield scan-source (defanged, not real).
const { exec } = require("child_process");

// VULN: OS command injection — exec with a template literal interpolating input
function resize(videoPath, width, height, outPath) {
  exec(`ffmpeg -i "${videoPath}" -vf scale=${width}:${height} "${outPath}"`);
}

// VULN: prefix-match sandbox escape (startsWith on a path, no separator boundary)
function readFile(requestedPath, allowedRoot) {
  if (requestedPath.startsWith(allowedRoot)) {
    return require("fs").readFileSync(requestedPath);
  }
  throw new Error("denied");
}

// VULN: SSRF — fetch of a non-constant URL
async function fetchUrl(targetUrl) {
  return fetch(targetUrl);
}

module.exports = { resize, readFile, fetchUrl };
