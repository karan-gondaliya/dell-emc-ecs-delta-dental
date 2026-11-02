import base64
import http.cookiejar
import json
import platform
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ------------------------------- USER INPUTS (edit only these) -------------------------------
HOST = "your_host_ip"
USERNAME = r"your_username"  # keep the r prefix so a backslash (local\user) is not treated as an escape
PASSWORD = r"your_password"
PORTS = "your_port"  # a single port (e.g. "443") or several, comma-separated (e.g. "443, 8443")
# ---------------------------------------------------------------------------------------------

VERIFY_SSL = False
SCHEME = "https"
TIMEOUT = 15
PER_PAGE = 10  # sent as `per_page=` on every `.../instances` call so the array itself returns at most this many
# records (confirmed official parameter, default page size is 2000 if omitted - Dell_Unity_XT_Research.md:1026).
MAX_RECORDS = 10  # log-display safety net only - trims the printed JSON if a response ever exceeds PER_PAGE.
MAX_PRINT = 500_000

# Required on every request per the Unisphere Management REST API Programmer's Guide v5.1 - without it
# Unisphere treats the caller as a browser and redirects to the HTML login page instead of returning JSON.
REST_CLIENT_HEADER = {"X-EMC-REST-CLIENT": "true"}
SECRET_HEADERS = ("authorization", "cookie", "set-cookie", "emc-csrf-token")
SUMMARY = []
CALLS = [0]

# Resource types identified in Dell_Unity_XT_Datadog_Endpoints_UserStories.md, Section 5 ("Appendix - Full List
# of All Endpoints"), grouped the same way as that document. Each tuple is (resourceType, extra_query_or_None);
# `fields=` is no longer hardcoded here - it's built at runtime from the full attribute list the array itself
# reports for that type (see discover_fields()), so the log always reflects everything the array exposes.
HEALTH_HARDWARE = [
    ("basicSystemInfo", None),
    ("system", None),
    ("storageProcessor", None),
    ("disk", None),
    ("alert", None),
]
CAPACITY = [
    ("pool", None),
    ("filesystem", None),
    ("storageResource", "filter=type eq 8"),  # type 8 = LUN
]
PROTECTION = [
    ("snap", None),
    ("replicationSession", None),
]
CONNECTIVITY = [
    ("host", None),
    ("hostInitiator", None),
    ("nasServer", None),
]

# Known-safe fallback field lists (the original curated sets from the build plan's Section 2), used as the
# middle tier of the fallback ladder - mirrors PowerStore's "plain attributes" tier in ps_collection(), except
# derived from documented research instead of a live schema's object/array type info (Unity's /api/types/<type>
# metadata isn't confirmed to expose that per-attribute type classification the way PowerStore's OpenAPI spec does).
CURATED_FIELDS = {
    "basicSystemInfo": ["id", "model", "name", "softwareVersion", "apiVersion"],
    "system": ["id", "name", "health", "model"],
    "storageProcessor": ["id", "name", "health", "cpuUtilization", "model"],
    "disk": ["id", "name", "health", "slotNumber", "tierType", "rawSize"],
    "alert": ["id", "severity", "description", "component", "timestamp", "isAcknowledged"],
    "pool": ["id", "name", "health", "sizeTotal", "sizeFree", "sizeSubscribed", "sizeUsed", "tiers", "poolFastVP"],
    "filesystem": ["id", "name", "health", "sizeTotal", "sizeUsed", "pool"],
    "storageResource": ["id", "name", "sizeAllocated", "sizeTotal"],
    "snap": ["id", "storageResource", "creationTime", "size"],
    "replicationSession": ["id", "name", "status", "health", "syncState", "replicationType"],
    "host": ["id", "name", "type", "osType"],
    "hostInitiator": ["id", "health", "initiatorId", "paths"],
    "nasServer": ["id", "name", "health", "homeSP"],
    "metric": ["id", "name", "path", "type"],
    # Not independently confirmed field names (no official sample response was found for either resource in
    # this research) - best-effort guesses from the general shape described in the research doc, used only as
    # a last-resort fallback if full discovery fails; discover_fields() should supply the real names at runtime.
    "metricValue": ["path", "values"],
    "metricQueryResult": ["queryId", "timestamp", "values"],
}


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


def q(path):
    """URL-encode a path+query that may contain literal spaces/quotes (e.g. `filter=type eq 8`)."""
    if "?" not in path:
        return urllib.parse.quote(path, safe="/")
    base, query = path.split("?", 1)
    return urllib.parse.quote(base, safe="/") + "?" + urllib.parse.quote(query, safe="/?&=,:()@")


def call(opener, base, path, method="GET", headers=None, basic=None, body=None, show_body=True, max_bytes=2_000_000):
    """Send one request, write its details to the log and return dict(status, headers, body, json, error)."""
    hdrs = {"Accept": "application/json", "Content-Type": "application/json", **(headers or {})}
    if basic:
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % basic).encode("utf-8")).decode("ascii")
    data = b"" if method == "POST" else None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
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
    entries = data.get("entries") if isinstance(data, dict) else None
    if isinstance(entries, list) and len(entries) > MAX_RECORDS:
        data = dict(data, entries=entries[:MAX_RECORDS])
        more = len(entries) - MAX_RECORDS
    elif isinstance(data, list) and len(data) > MAX_RECORDS:
        data, more = data[:MAX_RECORDS], len(data) - MAX_RECORDS
    text = json.dumps(data, indent=2, ensure_ascii=False) if data is not None else out["body"]
    if more:
        text += "\n... (%d more entries not shown)" % more
    if len(text) > MAX_PRINT:
        text = text[:MAX_PRINT] + "\n... (truncated, %d more characters)" % (len(text) - MAX_PRINT)
    print("Response body:\n%s" % text)


def host_name():
    """HOST without a scheme, path or port, in case a URL was pasted."""
    import re

    host = re.sub(r"^[A-Za-z]+://", "", str(HOST).strip()).split("/")[0]
    return host.split(":")[0] if host.count(":") == 1 else host


def port_list():
    """Parse the PORTS USER INPUT - a single port or several, comma-separated - into a list of ints."""
    ports = []
    for part in str(PORTS).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except ValueError:
            print("  ignoring invalid port %r (not a number)" % part)
    return ports


def short(r):
    return "NO RESPONSE (%s)" % r["error"] if r["status"] is None else "HTTP %s" % r["status"]


def count(r):
    j = r["json"]
    if isinstance(j, dict) and isinstance(j.get("entries"), list):
        return len(j["entries"])
    if isinstance(j, list):
        return len(j)
    return "-"


def first_entry_value(r, field):
    """Pull one field out of the first entry of a Unisphere collection response, if present.

    Handles both possible shapes for a `compact=True` collection response: the standard `{"entries": [...]}`
    wrapper, and a bare top-level array `[{"content": {...}}, ...]` - a real `compact=True` example response
    this script was checked against was ambiguous between the two (it showed a single `{"content": {...}},`
    element with a trailing comma, consistent with either shape), so both are handled defensively rather than
    assuming one.
    """
    j = r["json"]
    entries = j.get("entries") if isinstance(j, dict) else j if isinstance(j, list) else None
    if isinstance(entries, list) and entries:
        content = entries[0].get("content") or {}
        return content.get(field)
    return None


def discover_fields(opener, base, csrf, creds, res, resource_type):
    """Discover every attribute Unisphere reports for a resource type via `GET /api/types/<type>?compact=True&
    fields=attributes.name` - confirmed directly from developer.dell.com's tutorials.md, section "How to get
    attributes of resource" (https://developer.dell.com/apis/3028/versions/5.2.0/docs/TUTORIALS/tutorials.md
    #how-to-get-attributes-of-resource). `fields=attributes.name` is mandatory here: a bare `GET /api/types/<type>`
    with no `fields=` hits the same "minimal stub" rule as every other Unity endpoint and returns only `name`
    for the type itself, no `attributes` array at all. Each attribute object in that official example has only
    a `name` key - no `type`/`description` - confirming there is no per-attribute type classification available
    to filter "plain" scalar fields from nested objects the way PowerStore's OpenAPI spec allows.
    Returns (field_names, csrf, raw_response); falls back to `["id"]` if the shape can't be parsed.
    """
    r, csrf = unity_get(opener, base, q("/api/types/%s?compact=True&fields=attributes.name" % resource_type),
                         csrf, creds, res)
    content = None
    j = r["json"]
    if isinstance(j, dict):
        content = j.get("content")
        if content is None:
            entries = j.get("entries")
            if isinstance(entries, list) and entries:
                content = entries[0].get("content")
    names = []
    if isinstance(content, dict):
        attrs = content.get("attributes") or []
        for a in attrs:
            if isinstance(a, dict):
                n = a.get("name")
                if n:
                    names.append(n)
            elif isinstance(a, str):
                names.append(a)
    return names, csrf, r


def unity_login(opener, base, creds, res):
    """Step 1: unauthenticated reachability check. Step 2: bootstrap login + capture EMC-CSRF-TOKEN."""
    pre = call(opener, base,
               q("/api/types/basicSystemInfo/instances?compact=True&fields=id,model,name,softwareVersion,"
                 "apiVersion&per_page=%d&page=1" % PER_PAGE),
               headers=REST_CLIENT_HEADER)
    say("  [Unity XT] GET /api/types/basicSystemInfo/instances (no auth, reachability) -> %s" % short(pre))
    if pre["status"] == 200:
        res["signals"].append("basicSystemInfo reachable without authentication")

    login = call(opener, base, "/api/types/user/instances", basic=creds, headers=REST_CLIENT_HEADER, show_body=False)
    say("  [Unity XT] GET /api/types/user/instances (login) -> %s" % short(login))
    csrf = login["headers"].get("emc-csrf-token")
    if csrf:
        say("  [Unity XT] login succeeded, EMC-CSRF-TOKEN captured (value redacted)")
        res["login_ok"] = True
    elif login["status"] == 401:
        res["signals"].append("credentials rejected (401) on login")
    else:
        res["signals"].append("login returned %s with no EMC-CSRF-TOKEN header" % short(login))
    return csrf


def unity_get(opener, base, path, csrf, creds, res, show_body=True):
    headers = dict(REST_CLIENT_HEADER)
    if csrf:
        headers["EMC-CSRF-TOKEN"] = csrf
    r = call(opener, base, path, headers=headers, show_body=show_body)
    if r["status"] in (401, 403):
        csrf = unity_login(opener, base, creds, res)
        headers["EMC-CSRF-TOKEN"] = csrf
        r = call(opener, base, path, headers=headers, show_body=show_body)
    return r, csrf


def unity_post(opener, base, path, csrf, body):
    headers = dict(REST_CLIENT_HEADER)
    if csrf:
        headers["EMC-CSRF-TOKEN"] = csrf
    return call(opener, base, path, method="POST", headers=headers, body=body)


def query_with_fallback(opener, base, csrf, creds, res, resource, discovered_fields, curated_fields, extra=None,
                         show_body=True):
    """Same ladder as PowerStore's ps_collection(): try the richest field set first; if the array rejects it
    (400 - e.g. a discovered attribute name it won't actually accept in fields=), fall back to a smaller,
    known-safe set; if that also fails, fall back to id only. Stops at the first response that isn't a 400,
    exactly like PowerStore's `if r["status"] != 400: break`.

    `per_page`/`page` are only independently confirmed against one resource type (`lun`) in the research, not
    every resource type queried here - if a 400 is actually caused by the pagination params themselves rather
    than the field list (an untested risk, not a confirmed one), all three field tiers above would otherwise
    fail for the same reason and wrongly mark the endpoint as failed. So after the field-list ladder is
    exhausted, one last retry drops `per_page`/`page` entirely (plain `id` only) to isolate that case before
    giving up on the endpoint.
    """
    tiers = []
    if discovered_fields:
        tiers.append(("%d discovered attributes" % len(discovered_fields), discovered_fields))
    if curated_fields and curated_fields != discovered_fields:
        tiers.append(("%d curated attributes" % len(curated_fields), curated_fields))
    tiers.append(("id only", ["id"]))

    r = None
    for label, fields in tiers:
        query = "/api/types/%s/instances?compact=True&fields=%s&per_page=%d&page=1" % (
            resource, ",".join(fields), PER_PAGE)
        if extra:
            query += "&" + extra
        r, csrf = unity_get(opener, base, q(query), csrf, creds, res, show_body=show_body)
        say("  [Unity XT] GET /api/types/%-20s (%s) -> %s, records: %s" % (resource, label, short(r), count(r)))
        if r["status"] != 400:
            return r, csrf

    # Every field tier still returned 400 even at `id` only - isolate whether per_page/page themselves are the
    # cause by retrying once more without them.
    query = "/api/types/%s/instances?compact=True&fields=id" % resource
    if extra:
        query += "&" + extra
    r2, csrf = unity_get(opener, base, q(query), csrf, creds, res, show_body=show_body)
    say("  [Unity XT] GET /api/types/%-20s (id only, no per_page/page) -> %s, records: %s"
        % (resource, short(r2), count(r2)))
    if r2["status"] != 400:
        say("  [Unity XT] NOTE: %s rejected per_page/page but accepted the request without them - this resource"
            " type may not support pagination params the way `lun` does." % resource)
        return r2, csrf
    return r, csrf


def run_group(opener, base, csrf, creds, res, label, endpoints):
    say("  -- %s --" % label)
    for resource, extra in endpoints:
        res["endpoints_total"] += 1
        fields, csrf, meta_r = discover_fields(opener, base, csrf, creds, res, resource)
        if fields:
            say("  [Unity XT] GET /api/types/%-20s -> %s, %d attributes discovered: %s"
                % (resource, short(meta_r), len(fields), ", ".join(fields)))
        else:
            say("  [Unity XT] GET /api/types/%-20s -> %s, could not discover attributes" % (resource, short(meta_r)))
        r, csrf = query_with_fallback(opener, base, csrf, creds, res, resource, fields, CURATED_FIELDS.get(resource),
                                       extra)
        if r["status"] != 200:
            res["endpoints_failed"].append(resource)
    return csrf


def run_fixed_query(opener, base, csrf, creds, res, name, path):
    """A query whose shape is fixed by the build plan itself (e.g. a groupby/aggregation call), not derived
    from per-resource field discovery."""
    res["endpoints_total"] += 1
    r, csrf = unity_get(opener, base, q(path), csrf, creds, res)
    say("  [Unity XT] GET %-45s -> %s, records: %s" % ("%s (%s)" % (path.split("?")[0], name), short(r), count(r)))
    if r["status"] != 200:
        res["endpoints_failed"].append(name)
    return csrf


def unity_performance(opener, base, csrf, creds, res):
    say("  -- Performance (metric / metricValue / metricRealTimeQuery / metricQueryResult) --")
    res["endpoints_total"] += 1
    fields, csrf, meta_r = discover_fields(opener, base, csrf, creds, res, "metric")
    if fields:
        say("  [Unity XT] GET /api/types/metric       -> %s, %d attributes discovered: %s"
            % (short(meta_r), len(fields), ", ".join(fields)))
    else:
        say("  [Unity XT] GET /api/types/metric       -> %s, could not discover attributes" % short(meta_r))
    cat, csrf = query_with_fallback(opener, base, csrf, creds, res, "metric", fields, CURATED_FIELDS.get("metric"),
                                     show_body=False)
    if cat["status"] != 200:
        res["endpoints_failed"].append("metric")

    path = first_entry_value(cat, "path")
    res["endpoints_total"] += 2  # metricValue + metricRealTimeQuery, attempted or not
    if not path:
        say("  [Unity XT] metricValue / metricRealTimeQuery -> skipped, no metric path discovered from catalog")
        res["endpoints_failed"].append("metricValue")
        res["endpoints_failed"].append("metricRealTimeQuery")
        return csrf

    mv_fields, csrf, mv_meta = discover_fields(opener, base, csrf, creds, res, "metricValue")
    if mv_fields:
        say("  [Unity XT] GET /api/types/metricValue    -> %s, %d attributes discovered: %s"
            % (short(mv_meta), len(mv_fields), ", ".join(mv_fields)))
    else:
        say("  [Unity XT] GET /api/types/metricValue    -> %s, could not discover attributes" % short(mv_meta))
    mv, csrf = query_with_fallback(opener, base, csrf, creds, res, "metricValue", mv_fields,
                                    CURATED_FIELDS.get("metricValue"), extra='filter=path EQ "%s"' % path)
    if mv["status"] != 200:
        res["endpoints_failed"].append("metricValue")

    real_time_interval = 60
    post = unity_post(opener, base, "/api/types/metricRealTimeQuery/instances", csrf,
                       body={"paths": [path], "interval": real_time_interval})
    say("  [Unity XT] POST /api/types/metricRealTimeQuery/instances (path=%s) -> %s" % (path, short(post)))
    query_id = None
    content = post["json"].get("content") if isinstance(post["json"], dict) else None
    if content:
        query_id = content.get("id")
    res["endpoints_total"] += 1  # metricQueryResult, attempted or not
    if post["status"] not in (200, 201) or not query_id:
        say("  [Unity XT] metricQueryResult -> skipped, no queryId returned")
        res["endpoints_failed"].append("metricRealTimeQuery")
        res["endpoints_failed"].append("metricQueryResult")
        return csrf

    # storops (the only source with concrete timing guidance - see Dell_Unity_XT_Research.md Section 5.8)
    # recommends waiting MORE than one full sampling interval before the first read, so the array has had a
    # chance to collect at least one sample. Reading back too early (e.g. after just 1-2s) will reliably come
    # back with 0 records - not a failure of the endpoint, just a premature read.
    wait_s = real_time_interval + 5
    say("  [Unity XT] waiting %ds (one %ds sampling interval + margin, per storops guidance) before reading"
        " metricQueryResult back..." % (wait_s, real_time_interval))
    time.sleep(wait_s)
    qr_fields, csrf, qr_meta = discover_fields(opener, base, csrf, creds, res, "metricQueryResult")
    if qr_fields:
        say("  [Unity XT] GET /api/types/metricQueryResult -> %s, %d attributes discovered: %s"
            % (short(qr_meta), len(qr_fields), ", ".join(qr_fields)))
    else:
        say("  [Unity XT] GET /api/types/metricQueryResult -> %s, could not discover attributes" % short(qr_meta))
    qr, csrf = query_with_fallback(opener, base, csrf, creds, res, "metricQueryResult", qr_fields,
                                    CURATED_FIELDS.get("metricQueryResult"), extra="filter=queryId EQ %s" % query_id)
    if qr["status"] != 200:
        res["endpoints_failed"].append("metricQueryResult")
    say("  [Unity XT] NOTE: no confirmed cleanup/delete call exists for metricRealTimeQuery (research gap) -"
        " this query (id=%s) is left open on the array after this script exits." % query_id)
    return csrf


def unity_logout(opener, base, csrf):
    if not csrf:
        say("  [Unity XT] logout -> skipped, no active session")
        return
    r = unity_post(opener, base, "/api/types/loginSessionInfo/action/logout", csrf, body={"localCleanupOnly": "true"})
    say("  [Unity XT] POST /api/types/loginSessionInfo/action/logout -> %s" % short(r))


def new_result():
    return {"login_ok": False, "signals": [], "endpoints_failed": [], "endpoints_total": 0}


def check_port(opener, port, creds, results):
    base = "%s://%s:%d" % (SCHEME, host_name(), int(port))
    say("\n=== %s ===" % base)
    res = results[port] = new_result()

    csrf = safe("login", unity_login, opener, base, creds, res)
    if not res["login_ok"]:
        say("  [Unity XT] login failed - skipping all authenticated endpoints on this port")
        return

    for label, group in (
        ("Health & Hardware", HEALTH_HARDWARE),
        ("Capacity", CAPACITY),
        ("Data Protection / DR", PROTECTION),
        ("Connectivity & Access", CONNECTIVITY),
    ):
        csrf = safe(label, run_group, opener, base, csrf, creds, res, label, group) or csrf

    # Fixed aggregation query (groupby/computed attributes) - not part of per-resource field discovery.
    csrf = safe(
        "Capacity aggregation",
        run_fixed_query,
        opener,
        base,
        csrf,
        creds,
        res,
        "pool groupby",
        "/api/types/pool/instances?compact=True&fields=type,total::@sum(sizeTotal),free::@sum(sizeFree)"
        "&groupby=type&per_page=%d&page=1" % PER_PAGE,
    ) or csrf

    csrf = safe("Performance", unity_performance, opener, base, csrf, creds, res) or csrf
    safe("logout", unity_logout, opener, base, csrf)


def verdict(results):
    lines = []
    for port, res in results.items():
        if res["login_ok"]:
            total = res["endpoints_total"]
            failed = len(res["endpoints_failed"])
            if failed == 0:
                lines.append("port %d: login OK, all %d endpoints returned data." % (port, total))
            else:
                lines.append(
                    "port %d: login OK, %d/%d endpoints failed: %s"
                    % (port, failed, total, ", ".join(res["endpoints_failed"]))
                )
        else:
            why = "; ".join(res["signals"]) or "no response"
            lines.append("port %d: login FAILED (%s) - no endpoints were queried." % (port, why))
    return "\n".join(lines) if lines else "No ports were checked."


def print_summary(results):
    print("\n" + "=" * 100 + "\nSUMMARY\n" + "=" * 100)
    for line in SUMMARY:
        print(line)
    print("\n=== VERDICT ===")
    print(safe("verdict", verdict, results) or "Could not work out a verdict - please send the full output.")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    unchanged = [
        n for n, v in (("HOST", HOST), ("USERNAME", USERNAME), ("PASSWORD", PASSWORD), ("PORTS", PORTS))
        if str(v).startswith("your_")
    ]
    if unchanged:
        print("Edit the USER INPUTS at the top of the script first (still placeholder: %s)." % ", ".join(unchanged))
        return 1
    print("Run at %s UTC, Python %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), platform.python_version()))
    ports = port_list()
    if not ports:
        print("No valid ports parsed from PORTS=%r - edit the USER INPUTS at the top of the script." % PORTS)
        return 1
    print("Host %s, ports %s. API call details first, summary and verdict at the end." % (host_name(), ports))
    user = str(USERNAME)
    say("Username as sent: %r (length %d)" % (user, len(user)))

    opener, creds, results = build_opener(), (user, str(PASSWORD)), {}
    for port in ports:
        safe("port %s" % port, check_port, opener, port, creds, results)
    safe("summary", print_summary, results)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("Unexpected error, please send this output: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
