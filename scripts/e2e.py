#!/usr/bin/env python3
"""DranzoRMM end-to-end test: real server, real Go agent, real PostgreSQL.

Signs in as the bootstrap administrator (enrolling TOTP on a fresh stack), creates an organization and an
enrollment token, starts a Linux/macOS agent, waits for it to come online with inventory, runs a script on it
and checks live results, the audit trail and the audit hash chain. Standard library only.

  # against the compose stack (starts the `agent` profile itself):
  scripts/e2e.py --dashboard http://localhost:8081 --agent compose

  # against a locally running server and a locally built agent binary:
  scripts/e2e.py --dashboard http://localhost:8080 --agent native --agent-binary ./dranzo-agent \
                 --agent-url https://localhost:8443

Environment: DRANZO_ADMIN_EMAIL, DRANZO_ADMIN_PASSWORD (same values the server was bootstrapped with).
"""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent


def totp(secret_b32: str, at: float) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(at // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


class Api:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None
        self.secret = None
        self.last_step = 0

    def call(self, method, path, body=None, ok=(200, 201, 202, 204), raw=False):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.csrf and method not in ("GET", "HEAD"):
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req, timeout=60) as resp:
                status, payload, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            status, payload, headers = e.code, e.read(), e.headers
        if ok is not None and status not in ok:
            raise AssertionError(f"{method} {path} -> {status} {payload[:400]!r}")
        if raw:
            return status, payload, headers
        return status, (json.loads(payload) if payload else None)

    def code(self) -> str:
        # Never reuse a time step: the server rejects replayed codes.
        while int(time.time() // 30) <= self.last_step:
            time.sleep(1)
        self.last_step = int(time.time() // 30)
        return totp(self.secret, time.time())

    def login(self, email, password, state_file: pathlib.Path):
        if state_file.exists():
            saved = json.loads(state_file.read_text())
            if saved.get("email") == email and saved.get("base") == self.base:
                self.secret = saved["secret"]
        _, r = self.call("POST", "/api/v1/auth/login", {"email": email, "password": password})
        challenge = r["challengeToken"]
        if r["status"] == "mfa_enrollment_required":
            _, start = self.call("POST", "/api/v1/auth/mfa/enroll/start", {"challengeToken": challenge})
            self.secret = start["secret"]
            state_file.write_text(json.dumps({"email": email, "base": self.base, "secret": self.secret}))
            os.chmod(state_file, 0o600)
            _, done = self.call("POST", "/api/v1/auth/mfa/enroll/verify", {"challengeToken": challenge, "code": self.code()})
        else:
            if not self.secret:
                raise SystemExit(f"The administrator already has an authenticator and {state_file} does not hold its seed. "
                                 "Use a fresh stack (docker compose down -v) or point --state at the right file.")
            status, done = self.call("POST", "/api/v1/auth/mfa/verify", {"challengeToken": challenge, "code": self.code()}, ok=(200, 401))
            if status == 401:
                # The current code was already used by an earlier run (the server refuses replays): take the next one.
                status, done = self.call("POST", "/api/v1/auth/mfa/verify", {"challengeToken": challenge, "code": self.code()})
        self.csrf = done["csrfToken"]

    def step_up(self):
        self.call("POST", "/api/v1/auth/step-up", {"code": self.code()})


def wait_for(what, fn, timeout=120, every=1.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except (AssertionError, urllib.error.URLError, ConnectionError, OSError) as e:
            last = e
        time.sleep(every)
    raise AssertionError(f"timed out waiting for {what}; last: {last!r}")


def step(msg):
    print(f"  ✓ {msg}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dashboard", default="http://localhost:8081")
    ap.add_argument("--agent", choices=["compose", "native", "none"], default="compose")
    ap.add_argument("--agent-binary")
    ap.add_argument("--agent-url", default="https://localhost:8443", help="agent gateway URL for --agent native")
    ap.add_argument("--compose-file", default=str(ROOT / "deploy" / "docker-compose.yml"))
    ap.add_argument("--env-file", default=str(ROOT / ".env"))
    ap.add_argument("--state", default=str(ROOT / "deploy" / ".e2e-state.json"))
    ap.add_argument("--keep-agent", action="store_true")
    ap.add_argument("--update-binary", help="agent binary (for the device's OS/arch) to roll out as a signed update")
    ap.add_argument("--update-version", default="0.9.0")
    args = ap.parse_args()

    email = os.environ.get("DRANZO_ADMIN_EMAIL", "admin@example.test")
    password = os.environ.get("DRANZO_ADMIN_PASSWORD")
    if not password:
        raise SystemExit("Set DRANZO_ADMIN_PASSWORD (the bootstrap administrator password).")

    api = Api(args.dashboard)
    print("DranzoRMM end-to-end test against", args.dashboard)
    wait_for("the dashboard API", lambda: api.call("GET", "/healthz", ok=(200,))[0] == 200, timeout=180)
    step("server is healthy")

    status, _, headers = api.call("GET", "/api/v1/devices", ok=None, raw=True)
    assert status == 401, f"anonymous API access should be 401, got {status}"
    assert "nosniff" in (headers.get("X-Content-Type-Options") or ""), "security headers missing"
    assert api.call("POST", "/agent/v1/enroll", {"token": "x"}, ok=None)[0] == 404, "agent endpoints must not be on the dashboard listener"
    step("anonymous access denied; agent gateway not exposed on the dashboard listener")

    api.login(email, password, pathlib.Path(args.state))
    _, me = api.call("GET", "/api/v1/auth/me")
    assert "scripts.run" in me["permissions"]
    step(f"signed in as {me['user']['email']} with password + TOTP")

    suffix = time.strftime("%H%M%S")
    _, org = api.call("POST", "/api/v1/organizations", {"name": f"E2E Org {suffix}", "consentMode": "none"})
    _, site = api.call("POST", "/api/v1/sites", {"organizationId": org["id"], "name": "HQ"})
    _, group = api.call("POST", "/api/v1/groups", {"siteId": site["id"], "name": "Servers"})
    _, token = api.call("POST", "/api/v1/enrollment-tokens", {"siteId": site["id"], "groupId": group["id"], "name": "e2e", "maxUses": 1})
    step("organization, site, group and a single-use enrollment token created")

    proc = None
    tmp = None
    compose = ["docker", "compose", "-f", args.compose_file] + (["--env-file", args.env_file] if os.path.exists(args.env_file) else [])
    try:
        if args.agent == "compose":
            env = dict(os.environ, DRANZO_ENROLL_TOKEN=token["token"])
            subprocess.run(compose + ["--profile", "agent", "rm", "-sfv", "agent"], env=env, check=False, capture_output=True)
            subprocess.run(["docker", "volume", "rm", "-f", "dranzormm_agentdata"], check=False, capture_output=True)
            subprocess.run(compose + ["--profile", "agent", "up", "-d", "--build", "agent"], env=env, check=True)
        elif args.agent == "native":
            _, info = api.call("GET", "/api/v1/agent/install-info")
            tmp = tempfile.mkdtemp(prefix="dz-e2e-agent-")
            os.chmod(tmp, 0o700)
            for name, content in (("ca.pem", info["caCertificatePem"]), ("trust.json", json.dumps(info["trust"])),
                                  ("bootstrap.json", json.dumps({"serverUrl": args.agent_url, "token": token["token"]}))):
                p = pathlib.Path(tmp, name)
                p.write_text(content)
                os.chmod(p, 0o600)
            log = open(os.path.join(tmp, "stdout.log"), "wb")
            proc = subprocess.Popen([args.agent_binary, "run", "--foreground", "--data-dir", tmp], stdout=log, stderr=subprocess.STDOUT)

        def online():
            _, d = api.call("GET", f"/api/v1/devices?organizationId={org['id']}&online=true")
            return d["items"][0] if d["total"] == 1 else None

        device = wait_for("the agent to enroll and come online", online, timeout=240, every=2)
        step(f"agent enrolled over mTLS and is online: {device['hostname']} ({device['os']}/{device['arch']}, agent {device['agentVersion']})")

        detail = wait_for("inventory", lambda: (lambda d: d if d.get("inventory") else None)(api.call("GET", f"/api/v1/devices/{device['id']}")[1]), timeout=90)
        inv = detail["inventory"]
        assert inv["cpu"]["logicalCores"] >= 1 and inv["memoryBytes"] > 0 and inv["disks"], "inventory looks empty"
        step(f"inventory received: {inv['os']['name']} {inv['os']['version']}, {inv['cpu']['logicalCores']} CPUs, {inv['memoryBytes'] // 2**20} MiB RAM, {len(inv['disks'])} disk(s)")

        body = 'echo "dz-e2e-$((6*7)) $GREETING"\nid -u\necho to-stderr 1>&2\nexit 3\n'
        _, script = api.call("POST", "/api/v1/scripts", {"name": f"e2e {suffix}", "language": "sh", "body": body,
                                                         "parameters": [{"name": "GREETING", "type": "string", "required": True}]})
        _, job = api.call("POST", "/api/v1/jobs/run-script", {"scriptId": script["id"], "target": {"deviceIds": [device["id"]]},
                                                              "parameters": {"GREETING": "hello"}, "timeoutSeconds": 60})
        run_id = job["runs"][0]["id"]

        def finished():
            _, r = api.call("GET", f"/api/v1/runs/{run_id}")
            return r if r["status"] not in ("pending", "dispatched", "running") else None

        run = wait_for("the script run to finish", finished, timeout=90)
        output = "".join(c["data"] for c in run["output"])
        assert run["status"] == "failed" and run["exitCode"] == 3, f"expected exit code 3, got {run['status']} {run['exitCode']}"
        assert "dz-e2e-42 hello" in output and "to-stderr" in output, f"unexpected output: {output!r}"
        assert run["outputSha256"] == hashlib.sha256(output.encode()).hexdigest(), "output hash mismatch"
        step("signed script job ran on the device: live output, stderr, exit code 3 and matching output hash")

        _, audit = api.call("GET", f"/api/v1/audit?deviceId={device['id']}&pageSize=100")
        actions = {e["action"] for e in audit["items"]}
        assert {"device.enroll", "job.dispatch", "job.result"} <= actions, f"audit trail incomplete: {actions}"
        dispatch = next(e for e in audit["items"] if e["action"] == "job.dispatch")
        assert dispatch["contentSha256"] == hashlib.sha256(body.encode()).hexdigest(), "audit does not carry the script hash"
        _, verify = api.call("GET", "/api/v1/audit/verify")
        assert verify["ok"], f"audit chain broken: {verify}"
        step(f"audit trail complete (script hash recorded) and hash chain verifies over {verify['count']} events")

        # Object storage round trip: upload a (dummy) package, the server must report its SHA-256.
        blob = os.urandom(4096)
        req = urllib.request.Request(api.base + "/api/v1/packages/upload?fileName=e2e-dummy.deb", data=blob, method="PUT")
        req.add_header("X-CSRF-Token", api.csrf)
        req.add_header("Content-Type", "application/octet-stream")
        with api.opener.open(req, timeout=60) as resp:
            uploaded = json.loads(resp.read())
        assert uploaded["sha256"] == hashlib.sha256(blob).hexdigest() and uploaded["sizeBytes"] == len(blob), "upload hash mismatch"
        step("package upload stored in object storage with a server-computed SHA-256")

        caps = set(detail.get("capabilities") or [])
        if "software.scan" in caps:
            wait_for("software inventory", lambda: len(api.call("GET", f"/api/v1/devices/{device['id']}/software")[1]) > 0, timeout=180, every=3)
            step("software inventory reported")
        if "posture.scan" in caps:
            wait_for("security posture", lambda: api.call("GET", f"/api/v1/devices/{device['id']}/posture")[1] is not None, timeout=180, every=3)
            step("security posture reported")
        if "session.files" in caps:
            api.step_up()
            _, s = api.call("POST", f"/api/v1/devices/{device['id']}/sessions/files", {})
            wait_for("the files session to become active", lambda: api.call("GET", f"/api/v1/sessions/{s['sessionId']}")[1]["state"] == "active", timeout=60)
            _, listing = api.call("POST", f"/api/v1/sessions/{s['sessionId']}/files/list", {"path": "/"})
            assert any(e["name"] in ("etc", "usr", "bin", "Users") for e in listing["entries"]), "root listing looks wrong"
            api.call("POST", f"/api/v1/sessions/{s['sessionId']}/end")
            step("remote file session: consent mode applied, directory listed through a signed, session-bound job, session ended")

        if args.update_binary:
            data = pathlib.Path(args.update_binary).read_bytes()
            api.step_up()
            req = urllib.request.Request(api.base + "/api/v1/releases/upload?fileName=dranzo-agent", data=data, method="PUT")
            req.add_header("X-CSRF-Token", api.csrf)
            with api.opener.open(req, timeout=300) as resp:
                blob = json.loads(resp.read())
            assert blob["sha256"] == hashlib.sha256(data).hexdigest()
            _, rel = api.call("POST", "/api/v1/releases", {"version": args.update_version, "notes": "e2e",
                                                           "binaries": [{"os": device["os"], "arch": device["arch"], "blobId": blob["blobId"]}]})
            api.call("POST", f"/api/v1/releases/{rel['id']}/rollout", {"ring": "all"})
            wait_for(f"the agent to update itself to {args.update_version}",
                     lambda: api.call("GET", f"/api/v1/devices/{device['id']}")[1]["agentVersion"] == args.update_version, timeout=300, every=3)
            wait_for("the agent to confirm the update",
                     lambda: any(d["state"] == "installed" for d in api.call("GET", f"/api/v1/releases/{rel['id']}/devices")[1]), timeout=120, every=3)
            step(f"signed self-update: server offered {args.update_version}, agent verified, swapped, reconnected and confirmed 'installed'")

        api.step_up()
        api.call("POST", f"/api/v1/devices/{device['id']}/revoke")
        wait_for("the revoked device to go offline", lambda: not api.call("GET", f"/api/v1/devices/{device['id']}")[1]["isOnline"], timeout=60)
        time.sleep(5)
        assert api.call("GET", f"/api/v1/devices/{device['id']}")[1]["status"] == "revoked"
        assert not api.call("GET", f"/api/v1/devices/{device['id']}")[1]["isOnline"], "a revoked device reconnected"
        step("device revoked: certificate invalidated, connection dropped, cannot reconnect")
        print("PASS")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        if args.agent == "compose" and not args.keep_agent:
            subprocess.run(compose + ["--profile", "agent", "rm", "-sfv", "agent"], check=False, capture_output=True)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print("FAIL:", e, file=sys.stderr)
        sys.exit(1)
