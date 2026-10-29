r"""Identify whether a management IP is a Dell EMC ECS or a Dell PowerStore, show its version and, for PowerStore,
collect sample data from its main REST API endpoints.

Edit only the USER INPUTS below. Then open Command Prompt (cmd.exe) in the folder that contains this file and run:
    "C:\Program Files\Datadog\Datadog Agent\embedded3\python.exe" ^
    dell_emc_ecs_delta_dental_troubleshoot.py > delta-dental.log
The log lists every API call with its response first, then the summary and the verdict at the end.
Only reads data (GET requests, plus the PowerStore metrics query and logout). Passwords and tokens are never printed.
"""

import base64
import http.cookiejar
import json
import platform
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ------------------------------- USER INPUTS (edit only these) -------------------------------
HOST = "your_host_ip"
USERNAME = r"your_username"  # keep the r prefix so a backslash (DOMAIN\user) is not treated as an escape
PASSWORD = r"your_password"
PORTS = [443, 4443, 8443]
# ---------------------------------------------------------------------------------------------

VERIFY_SSL = False
SCHEME = "https"
TIMEOUT = 15
MAX_RECORDS = 10
MAX_PRINT = 500_000

# Documented in the PowerStore REST API Developers Guide or Dell KB 000490125; always queried.
PS_CORE = [
    "appliance",
    "node",
    "hardware",
    "alert",
    "event",
    "audit_event",
    "replication_session",
    "volume",
    "volume_group",
    "storage_container",
]
# Queried only when the device's own API spec (/api/rest/openapi.json) lists them.
PS_OTHER = ["cluster", "software_installed", "host", "file_system"]
PS_METRICS = [
    "performance_metrics_by_cluster",
    "space_metrics_by_cluster",
    "performance_metrics_by_appliance",
    "space_metrics_by_appliance",
]
SECRET_HEADERS = ("authorization", "cookie", "set-cookie", "dell-emc-token", "x-sds-auth-token")
SUMMARY = []
CALLS = [0]


def say(line=""):
    SUMMARY.append(line)


def safe(label, fn, *args, **kwargs):
    """Run one step; on any error note it in the summary and carry on, so the script always runs to the end."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        say("  [%s] step failed, continuing: %s: %s" % (label, type(e).__name__, e))
        return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects, so the credentials are only ever sent to the configured host."""

    def redirect_request(self, *args, **kwargs):
        return None


def build_opener():
    ctx = ssl.create_default_context()
    if not VERIFY_SSL:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    handlers = (urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar), NoRedirect())
    return urllib.request.build_opener(*handlers)


def call(opener, base, path, method="GET", headers=None, basic=None, body=None, show_body=True, max_bytes=2_000_000):
    """Send one request, write its details to the log and return dict(status, headers, body, json, error)."""
    hdrs = {"Accept": "application/json", **(headers or {})}
    if basic:
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % basic).encode("utf-8")).decode("ascii")
    data = b"" if method == "POST" else None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    out = {"status": None, "headers": {}, "body": "", "json": None, "error": None, "elapsed": 0.0}
    start = time.time()
    try:
        req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
        resp = opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception as e:
        resp = None
        out["error"] = "%s: %s" % (type(e).__name__, e)
    if resp is not None:
        try:
            out["status"] = resp.getcode()
            out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
            out["body"] = resp.read(max_bytes).decode("utf-8", "replace")
            out["json"] = json.loads(out["body"])
        except json.JSONDecodeError:
            pass
        except Exception as e:
            out["error"] = "%s: %s" % (type(e).__name__, e)
    out["elapsed"] = time.time() - start
    safe("log", log_call, method, base + path, hdrs, body, out, show_body)
    return out


def log_call(method, url, hdrs, body, out, show_body):
    CALLS[0] += 1
    print("-" * 100)
    print("[CALL %d] %s %s" % (CALLS[0], method, url))
    shown = ["%s: %s" % (k, "<redacted>" if k.lower() in SECRET_HEADERS else v) for k, v in hdrs.items()]
    print("Request headers: %s" % ", ".join(shown))
    if body is not None:
        print("Request body: %s" % json.dumps(body))
    if out["status"] is None:
        print("Response: NO RESPONSE (%s) after %.2f s" % (out["error"], out["elapsed"]))
        return
    meta = ["HTTP %s" % out["status"]]
    meta += ["%s: %s" % (k, v) for k, v in out["headers"].items() if k in ("content-type", "content-range")]
    meta += ["%d characters" % len(out["body"]), "%.2f s" % out["elapsed"]]
    if out["error"]:
        meta.append("read error: %s" % out["error"])
    print("Response: %s" % " | ".join(meta))
    if not show_body:
        print("Response body: not shown")
        return
    data, more = out["json"], 0
    if isinstance(data, list) and len(data) > MAX_RECORDS:
        data, more = data[:MAX_RECORDS], len(data) - MAX_RECORDS
    text = json.dumps(data, indent=2, ensure_ascii=False) if data is not None else out["body"]
    if more:
        text += "\n... (%d more objects not shown)" % more
    if len(text) > MAX_PRINT:
        text = text[:MAX_PRINT] + "\n... (truncated, %d more characters)" % (len(text) - MAX_PRINT)
    print("Response body:\n%s" % text)


def find_versions(obj, path="", found=None, limit=12):
    """Collect (path, value) for JSON keys containing 'version'."""
    found = [] if found is None else found
    if len(found) >= limit:
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (path, k) if path else k
            if re.search("version", str(k), re.I) and isinstance(v, (str, int, float)):
                found.append((p, v))
            else:
                find_versions(v, p, found, limit)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            find_versions(v, "%s[%d]" % (path, i), found, limit)
    return found


def host_name():
    """HOST without a scheme, path or port, in case a URL was pasted."""
    host = re.sub(r"^[A-Za-z]+://", "", str(HOST).strip()).split("/")[0]
    return host.split(":")[0] if host.count(":") == 1 else host


def port_list():
    return list(PORTS) if isinstance(PORTS, (list, tuple)) else [PORTS]


def short(r):
    return "NO RESPONSE (%s)" % r["error"] if r["status"] is None else "HTTP %s" % r["status"]


def count(r):
    return len(r["json"]) if isinstance(r["json"], list) else "-"


def new_result():
    return {"signals": [], "confirmed": False, "version": []}


def ps_call(opener, base, path, hdrs, creds, **kwargs):
    """PowerStore call using the session cookie; if the session is refused, resend the credentials once."""
    r = call(opener, base, path, headers=hdrs, **kwargs)
    if r["status"] == 401:
        r = call(opener, base, path, headers=hdrs, basic=creds, **kwargs)
    return r


def spec_paths(spec):
    paths = {}
    for p, v in (spec.get("paths") or {}).items():
        paths[p[len("/api/rest") :] if p.startswith("/api/rest") else p] = v
    return paths


def spec_attributes(spec, paths, resource):
    """Attribute names of a resource, read from the device's own API spec (Swagger 2 or OpenAPI 3)."""
    defs = spec.get("definitions") or spec.get("components", {}).get("schemas", {})
    ok = paths.get("/" + resource, {}).get("get", {}).get("responses", {}).get("200", {})
    schema = ok.get("schema") or ok.get("content", {}).get("application/json", {}).get("schema") or {}
    ref = (schema.get("items") or schema).get("$ref")
    definition = defs.get(ref.split("/")[-1] if ref else resource + "_instance", {})
    props = {}
    for part in [definition] + definition.get("allOf", []):
        if "$ref" in part:
            part = defs.get(part["$ref"].split("/")[-1], {})
        props.update(part.get("properties", {}))
    return props


def ps_spec(opener, base, hdrs, creds):
    r = ps_call(opener, base, "/api/rest/openapi.json", hdrs, creds, show_body=False, max_bytes=200_000_000)
    spec = r["json"] if isinstance(r["json"], dict) and "paths" in r["json"] else None
    if not spec:
        say("  [PowerStore] GET /api/rest/openapi.json -> %s, API spec not available (core endpoints only)" % short(r))
        return None, {}
    paths = spec_paths(spec)
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    gets = sorted(p for p, v in paths.items() if isinstance(v, dict) and "get" in v and "{" not in p)
    say(
        "  [PowerStore] GET /api/rest/openapi.json -> %s, %s %s, %d documented collection endpoints (listed in the log)"
        % (short(r), info.get("title"), info.get("version"), len(gets))
    )
    print("Documented GET collection endpoints in this device's API spec (%d):" % len(gets))
    for p in gets:
        print("  GET /api/rest%s" % p)
    return spec, paths


def ps_collection(opener, base, hdrs, creds, resource, spec, paths, store):
    props = (safe("PowerStore", spec_attributes, spec, paths, resource) if spec else None) or {}
    names = [str(k) for k in props]
    plain = [str(k) for k, v in props.items() if isinstance(v, dict) and "$ref" not in v]
    plain = [k for k in plain if props[k].get("type") not in ("object", "array")]
    attempts = []
    for label, attrs in (("%d attributes" % len(names), names), ("%d plain attributes" % len(plain), plain)):
        if attrs and (attrs is names or len(plain) < len(names)):
            select = urllib.parse.quote(",".join(attrs), safe=",")
            attempts.append((label, "?limit=%d&select=%s" % (MAX_RECORDS, select)))
    attempts.append(("id only", ""))
    for label, query in attempts:
        r = ps_call(opener, base, "/api/rest/%s%s" % (resource, query), hdrs, creds)
        say("  [PowerStore] GET /api/rest/%-20s (%s) -> %s, records: %s" % (resource, label, short(r), count(r)))
        if r["status"] != 400:
            break
    if r["status"] in (200, 206) and isinstance(r["json"], list):
        store[resource] = r["json"]


def ps_metrics(opener, base, hdrs, creds, store):
    for entity in PS_METRICS:
        scope = entity.rsplit("_", 1)[-1]
        items = store.get(scope) or []
        entity_id = items[0].get("id") if items and isinstance(items[0], dict) else None
        if not entity_id:
            say("  [PowerStore] POST /api/rest/metrics/generate %s -> skipped, no %s id" % (entity, scope))
            continue
        body = {"entity": entity, "entity_id": entity_id, "interval": "Five_Mins"}
        r = ps_call(opener, base, "/api/rest/metrics/generate", hdrs, creds, method="POST", body=body)
        say("  [PowerStore] POST /api/rest/metrics/generate %s -> %s, records: %s" % (entity, short(r), count(r)))


def probe_powerstore(opener, base, creds, res):
    r = call(opener, base, "/api/rest/login_session", basic=creds)
    say("  [PowerStore] GET /api/rest/login_session -> %s" % short(r))
    if r["status"] == 200 and isinstance(r["json"], list):
        res["confirmed"] = True
        res["signals"].append("PowerStore login succeeded")
        token = r["headers"].get("dell-emc-token")
        hdrs = {"DELL-EMC-TOKEN": token} if token else {}
        spec, paths = safe("PowerStore", ps_spec, opener, base, hdrs, creds) or (None, {})
        store = {}
        for resource in PS_CORE + PS_OTHER:
            if resource in PS_OTHER and "/" + resource not in paths:
                why = "not in this device's API spec" if spec else "API spec not available to confirm it"
                say("  [PowerStore] GET /api/rest/%-20s -> skipped, %s" % (resource, why))
                continue
            safe("PowerStore", ps_collection, opener, base, hdrs, creds, resource, spec, paths, store)
        safe("PowerStore", ps_metrics, opener, base, hdrs, creds, store)
        for resource in ("software_installed", "cluster", "appliance"):
            res["version"].extend(safe("PowerStore", find_versions, store.get(resource)) or [])
        safe("PowerStore", call, opener, base, "/api/rest/logout", method="POST", headers=hdrs)
    elif r["status"] == 401:
        res["signals"].append("PowerStore API reachable but the credentials were rejected (401)")


def ecs_read(opener, base, hdrs, path, res):
    c = call(opener, base, path, headers=hdrs)
    say("  [ECS]        GET %s -> %s" % (path, short(c)))
    if c["status"] == 200 and c["json"] is not None:
        res["version"].extend(find_versions(c["json"]))


def probe_ecs(opener, base, creds, res):
    r = call(opener, base, "/login", basic=creds)
    say("  [ECS]        GET /login -> %s" % short(r))
    token = r["headers"].get("x-sds-auth-token")
    if r["status"] == 200 and token:
        res["confirmed"] = True
        res["signals"].append("ECS login succeeded (X-SDS-AUTH-TOKEN returned)")
        hdrs = {"X-SDS-AUTH-TOKEN": token}
        for path in ("/object/vdcs/vdc/list", "/vdc/nodes", "/dashboard/zones/localzone/nodes"):
            safe("ECS", ecs_read, opener, base, hdrs, path, res)
        safe("ECS", call, opener, base, "/logout", headers=hdrs)
    elif r["status"] == 401:
        res["signals"].append("ECS-style /login reachable but the credentials were rejected (401)")


def verdict(results):
    def ports(name, key):
        return [p for p, r in results.items() if r.get(name, {}).get(key)]

    ps_conf, ecs_conf = ports("powerstore", "confirmed"), ports("ecs", "confirmed")
    ps_sig, ecs_sig = ports("powerstore", "signals"), ports("ecs", "signals")
    if ps_conf and not ecs_conf:
        return "DELL POWERSTORE confirmed on port(s) %s. The ECS integration cannot collect from it." % ps_conf
    if ecs_conf and not ps_conf:
        return "DELL EMC ECS confirmed on port(s) %s. Use that port in conf.yaml." % ecs_conf
    if ps_conf and ecs_conf:
        return "Both product APIs answered (PowerStore=%s, ECS=%s) - send the full output." % (ps_conf, ecs_conf)
    if ps_sig and not ecs_sig:
        return "Looks like DELL POWERSTORE (/api/rest/... exists on %s) but login was not completed." % ps_sig
    if ecs_sig and not ps_sig:
        return "Looks like DELL EMC ECS (/login exists on %s) but login was not completed." % ecs_sig
    return "Neither product's API answered on ports %s (404 or no response)." % port_list()


def check_port(opener, port, creds, results):
    base = "%s://%s:%d" % (SCHEME, host_name(), int(port))
    say("\n=== %s ===" % base)
    r = call(opener, base, "/", show_body=False)
    if r["status"] is None and "CERTIFICATE" not in str(r["error"]).upper():
        say("  not reachable: %s" % r["error"])
        return
    res = results[port] = {"powerstore": new_result(), "ecs": new_result()}
    safe("PowerStore", probe_powerstore, opener, base, creds, res["powerstore"])
    safe("ECS", probe_ecs, opener, base, creds, res["ecs"])


def print_details(results):
    for port, res in results.items():
        for name, info in res.items():
            for s in info["signals"]:
                print("  port %d [%s]: %s" % (port, name, s))
            for p, val in info["version"][:6]:
                print("  port %d [%s] version field %s = %s" % (port, name, p, val))


def print_summary(results):
    print("\n" + "=" * 100 + "\nSUMMARY\n" + "=" * 100)
    for line in SUMMARY:
        print(line)
    print("\n=== VERDICT ===")
    print(safe("verdict", verdict, results) or "Could not work out a verdict - please send the full output.")
    safe("details", print_details, results)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    unchanged = [
        n for n, v in (("HOST", HOST), ("USERNAME", USERNAME), ("PASSWORD", PASSWORD)) if str(v).startswith("your_")
    ]
    if unchanged:
        print("Edit the USER INPUTS at the top of the script first (still placeholder: %s)." % ", ".join(unchanged))
        return 1
    print("Run at %s UTC, Python %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), platform.python_version()))
    print("Host %s, ports %s. API call details first, summary and verdict at the end." % (host_name(), port_list()))
    user = str(USERNAME)
    say("Username as sent: %r (length %d)" % (user, len(user)))
    if any(ord(c) < 32 for c in user):
        say('WARNING: the username has control characters - use a raw string, e.g. r"DOMAIN\\user".')

    opener, creds, results = build_opener(), (user, str(PASSWORD)), {}
    for port in port_list():
        safe("port %s" % port, check_port, opener, port, creds, results)
    safe("summary", print_summary, results)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("Unexpected error, please send this output: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
