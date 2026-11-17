#!/usr/bin/env python3
"""Preserve CI reports on the compute server using this job's GitHub OIDC token."""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

BASE_URL = "https://n8n.jubershaikh.com/ci-artifacts"
MAX_BYTES = 256 * 1024 * 1024
SLOTS = {'vitest-linux-node', 'deadcode-ts-unused-exports', 'deadcode-knip', 'deadcode-ts-prune', 'vitest-windows-node'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def report_files(source):
    if source.name.startswith(".") or source.is_symlink() or not source.exists():
        return
    if source.is_file():
        yield source
        return
    for root, directories, files in os.walk(source, followlinks=False):
        directories[:] = [name for name in directories if not name.startswith(".")]
        for name in files:
            entry = Path(root) / name
            if not name.startswith(".") and not entry.is_symlink() and entry.is_file():
                yield entry


def pack_reports(sources, destination):
    """Exclude hidden files and symlinks while preserving separate report roots."""
    count = 0
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for source in sources:
            for entry in report_files(source):
                name = source.name if entry == source else str(Path(source.name) / entry.relative_to(source))
                archive.write(entry, name)
                count += 1
    return count


def oidc_token(base_url):
    url = urllib.parse.urlsplit(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    if url.scheme != "https" or not (url.hostname or "").endswith(".actions.githubusercontent.com"):
        raise ValueError("Unexpected GitHub OIDC endpoint")
    query = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != "audience"] + [("audience", base_url)]
    request_url = urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(query)))
    request = urllib.request.Request(request_url)
    request.add_header("Authorization", "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"])
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        token = json.load(response)["value"]
    if not isinstance(token, str) or len(token) < 50:
        raise ValueError("GitHub returned an invalid OIDC token")
    return token


def upload(base_url, slot, archive, digest, size, token):
    target = urllib.parse.urlsplit(base_url)
    if target.scheme != "https" or not target.hostname or target.query or target.fragment or target.username or target.password:
        raise ValueError("Invalid compute report endpoint")
    connection = http.client.HTTPSConnection(target.hostname, target.port or 443, timeout=180,
                                             context=ssl.create_default_context())
    try:
        connection.putrequest("PUT", target.path.rstrip("/") + "/v1/artifacts/reports/" + slot)
        for name, value in {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(size),
            "X-Artifact-SHA256": digest,
            "X-Artifact-Format": "zip",
        }.items():
            connection.putheader(name, value)
        connection.endheaders()
        with archive.open("rb") as source:
            while block := source.read(1024 * 1024):
                connection.send(block)
        response = connection.getresponse()
        body = response.read(32769)
        if response.status >= 500 or response.status == 429:
            raise ConnectionError("Compute report receiver temporarily unavailable")
        if response.status not in (200, 201) or len(body) > 32768:
            raise ValueError(f"Compute report receiver rejected upload (HTTP {response.status})")
        return json.loads(body)
    finally:
        connection.close()


def verify_receipt(receipt, slot, digest, size):
    expected = {
        "repository": os.environ["GITHUB_REPOSITORY"],
        "repository_id": os.environ["GITHUB_REPOSITORY_ID"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "family": "reports",
        "slot": slot,
        "sha256": digest,
        "size_bytes": size,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError("Compute receipt does not match uploaded report: " + key)
    stored = receipt.get("path", "")
    if not isinstance(stored, str) or not stored or not re.fullmatch(r"[A-Za-z0-9_./-]+", stored):
        raise ValueError("Invalid stored report path")
    if stored.startswith("/") or ".." in Path(stored).parts:
        raise ValueError("Invalid stored report path")
    retained = datetime.fromisoformat(receipt["retained_until"].replace("Z", "+00:00"))
    if retained.tzinfo is None or retained <= datetime.now(timezone.utc):
        raise ValueError("Compute report retention has already expired")
    return stored


def store_report(slot, sources):
    with tempfile.TemporaryDirectory(prefix="compute-report-", dir=os.environ.get("RUNNER_TEMP")) as folder:
        archive = Path(folder) / "report.zip"
        if not pack_reports(sources, archive):
            print("No generated reports to preserve.")
            return
        if not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") and os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
            message = "GitHub withheld OIDC for this PR. Its detailed report could not be retained on compute."
            print("::warning::" + message)
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
                output.write(message + "\n")
            return
        size = archive.stat().st_size
        if size > MAX_BYTES:
            raise ValueError("Report exceeds the 256 MiB compute upload limit")
        with archive.open("rb") as source:
            checksum = hashlib.sha256()
            for block in iter(lambda: source.read(1024 * 1024), b""):
                checksum.update(block)
            digest = checksum.hexdigest()
        for attempt in range(3):
            try:
                token = oidc_token(BASE_URL)
                receipt = upload(BASE_URL, slot, archive, digest, size, token)
                stored = verify_receipt(receipt, slot, digest, size)
                break
            except (ConnectionError, TimeoutError, urllib.error.URLError, http.client.HTTPException):
                if attempt == 2:
                    raise RuntimeError("Compute report upload failed after three attempts") from None
                time.sleep(2 ** (attempt + 1))
        text = f"Report stored on private compute at `{stored}` ({size} bytes, SHA-256 `{digest}`)."
        print(text)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as output:
                output.write(text + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slot", choices=sorted(SLOTS))
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()
    store_report(args.slot, args.sources)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, RuntimeError, http.client.HTTPException) as error:
        # Avoid leaking signed URLs or request credentials in transport exceptions.
        print(f"::error::Private compute report retention failed ({type(error).__name__}).", file=sys.stderr)
        sys.exit(1)
