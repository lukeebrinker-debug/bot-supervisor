#!/usr/bin/env python3
"""
Bot supervisor: watches your other GitHub-Actions bots, fixes what it safely can,
alerts you on ntfy with step-by-step fixes, and locks a bot down if it looks tampered with.

  python supervisor.py --monitor    # check everything (runs every 15 min)
  python supervisor.py --report     # check + send the daily "all clear / problems" report
  python supervisor.py --status     # dry run: print findings, change nothing, send nothing
  python supervisor.py --accept     # I changed my code on purpose: re-record the trusted baseline
  python supervisor.py --reenable   # turn locked-down bots back on
  python supervisor.py --recover    # accept + reenable

Env: GH_TOKEN (fine-grained token), NTFY_TOPIC
"""
import hashlib, json, os, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

BASE = Path(__file__).parent
CONFIG = json.loads((BASE / "config.json").read_text())
STATE_FILE = BASE / "state.json"
GH = "https://api.github.com"
TOKEN = os.getenv("GH_TOKEN", "")
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "change-me")
ACT = True                      # False in --status mode (dry run)
FAIL = {"failure", "timed_out", "startup_failure"}
SELF_RUN_EVENTS = {"schedule", "workflow_dispatch"}
_token_expiry = None


# ------------------------------------------------------------------ GitHub API
class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"HTTP {status}: {msg}")
        self.status = status


def now_utc():
    return datetime.now(timezone.utc)


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def api(method, path, **kw):
    global _token_expiry
    r = requests.request(method, GH + path, timeout=30, headers={
        "Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"}, **kw)
    exp = r.headers.get("github-authentication-token-expiration")
    if exp:
        _token_expiry = exp
    if r.status_code >= 400:
        raise ApiError(r.status_code, r.text[:160])
    return r.json() if r.content else {}


def list_workflows(repo):
    return api("GET", f"/repos/{repo}/actions/workflows", params={"per_page": 100}).get("workflows", [])


def list_runs(repo, hours=26):
    since = (now_utc() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = []
    for page in range(1, 6):
        d = api("GET", f"/repos/{repo}/actions/runs",
                params={"created": f">={since}", "per_page": 100, "page": page}).get("workflow_runs", [])
        out += d
        if len(d) < 100:
            break
    return out


def file_shas(repo, files):
    out = {}
    try:
        for it in api("GET", f"/repos/{repo}/contents/.github/workflows"):
            out[it["path"]] = it["sha"]
    except ApiError as e:
        if e.status != 404:
            raise
    for p in files:
        try:
            out[p] = api("GET", f"/repos/{repo}/contents/{p}")["sha"]
        except ApiError as e:
            if e.status != 404:
                raise
            out[p] = "MISSING"
    return out


def _act(desc, method, path):
    if not ACT:
        print(f"   [dry-run] would {desc}")
        return
    api(method, path)


def enable_wf(repo, wid):  _act("enable workflow", "PUT", f"/repos/{repo}/actions/workflows/{wid}/enable")
def disable_wf(repo, wid): _act("disable workflow", "PUT", f"/repos/{repo}/actions/workflows/{wid}/disable")
def cancel_run(repo, rid): _act("cancel run", "POST", f"/repos/{repo}/actions/runs/{rid}/cancel")
def rerun_failed(repo, rid): _act("retry failed run", "POST", f"/repos/{repo}/actions/runs/{rid}/rerun-failed-jobs")


# ------------------------------------------------------------------ notifications
def notify(title, body, prio="default", tags="", url=None):
    print(f"NOTIFY [{prio}] {title}\n{body}\n")
    if not ACT:
        return
    h = {"Title": title.encode("ascii", "replace").decode(), "Priority": prio}
    if tags:
        h["Tags"] = tags
    if url:
        h["Click"] = url
    try:
        requests.post(f"https://ntfy.sh/{NTFY_TOPIC}", data=body.encode("utf-8"), headers=h, timeout=20)
    except Exception as e:
        print("ntfy failed:", e)


def F(sev, key, title, detail, fix, url=None):
    return {"sev": sev, "key": key, "title": title, "detail": detail, "fix": fix, "url": url}


def steps(lst):
    return "\n".join(f"{i}. {s}" for i, s in enumerate(lst, 1))


FIX_FAILED = ["Tap this message to open the failed run.",
              "Click 'hunt' (or the job name) on the left, then open the step with the red X.",
              "Copy the error text.",
              "Paste it to Claude and say 'fix this bot' - it will tell you exactly what to edit.",
              "Edit the file in GitHub (pencil icon) and click Commit changes.",
              "Actions tab > pick the workflow > Run workflow to test it."]
FIX_STALE = ["Open the bot's repo > Actions tab. Is the workflow listed and enabled?",
             "If it says disabled, click 'Enable workflow'.",
             "Click the workflow, then 'Run workflow' to start it manually.",
             "If it runs fine, the delay was GitHub's scheduler (common, usually self-heals).",
             "If it keeps going stale, check githubstatus.com, then message Claude with what you see."]
FIX_HACK = ["The bot has been STOPPED automatically (if auto-shutdown is on). You don't need to rush.",
            "Look at what changed: bot repo > Commits (who/what) and Actions tab (runs you don't recognize).",
            "If this was YOU editing files: supervisor repo > Actions > Bot supervisor > Run workflow > mode 'recover'.",
            "If it was NOT you: change your GitHub password now, make sure 2FA/passkey is on, and "
            "GitHub Settings > Sessions: revoke unknown devices.",
            "GitHub Settings > Developer settings > Personal access tokens: delete any you don't recognize.",
            "Bot repo > Settings > Collaborators: remove anyone unknown.",
            "Make a NEW ntfy topic and update the NTFY_TOPIC secret in that repo.",
            "Then run the supervisor with mode 'recover' to accept the clean code and turn the bot back on."]


# ------------------------------------------------------------------ checks
def check_repo(bot, st, now):
    repo, name = bot["repo"], bot["name"]
    owner = repo.split("/")[0].lower()
    actors = {owner} | {a.lower() for a in CONFIG.get("allowed_actors", [])}
    allowed = set(bot["workflows"])
    rs = st["repos"].setdefault(repo, {"baseline": {}, "retried": []})
    locked = repo in st["shutdown"]
    findings, auto = [], []
    repo_url = f"https://github.com/{repo}/actions"

    wfs = list_workflows(repo)
    runs = list_runs(repo)
    by_path = {w["path"]: w for w in wfs}
    allowed_ids = {w["id"] for w in wfs if w["path"] in allowed}
    dyn_ids = {w["id"] for w in wfs if w["path"].startswith("dynamic/")}

    # 1. workflows that shouldn't exist (a classic way attackers run code in your repo)
    for w in wfs:
        if w["path"] not in allowed and not w["path"].startswith("dynamic/"):
            findings.append(F("high", f"rogue:{repo}:{w['path']}", f"{name}: UNKNOWN WORKFLOW",
                              f"A workflow you didn't list exists: {w['path']}", FIX_HACK, repo_url))

    # 2. workflow state (auto-heal GitHub's inactivity pause)
    day = now.strftime("%Y%m%d")
    for p in allowed:
        w = by_path.get(p)
        if not w:
            findings.append(F("alert", f"missing:{repo}:{p}:{day}", f"{name}: workflow file missing",
                              f"{p} no longer exists in the repo.",
                              ["Open the repo and check the Commits page to see if it was deleted.",
                               "Re-create it (Add file > Create new file) using your saved copy, or ask Claude for it."],
                              repo_url))
        elif w["state"] == "disabled_inactivity" and not locked:
            enable_wf(repo, w["id"])
            auto.append(f"{name}: re-enabled '{w['name']}' (GitHub paused it for inactivity)")
        elif w["state"] == "disabled_manually" and not locked:
            findings.append(F("alert", f"disabled:{repo}:{p}:{day}", f"{name}: workflow is turned off",
                              f"'{w['name']}' is disabled.",
                              ["Open the repo > Actions tab > click the workflow.",
                               "Click 'Enable workflow'. (If you didn't turn it off, treat it as suspicious.)"], repo_url))

    # 3. tamper detection: compare file fingerprints with the trusted baseline
    cur = file_shas(repo, bot.get("watch_files", []))
    if not rs["baseline"]:
        rs["baseline"] = cur
        auto.append(f"{name}: trusted baseline recorded ({len(cur)} files)")
    else:
        changed = sorted(p for p in set(cur) | set(rs["baseline"]) if cur.get(p) != rs["baseline"].get(p))
        if changed:
            wf_changed = [p for p in changed if p.startswith(".github/workflows/")]
            sev = "high" if (wf_changed or CONFIG.get("shutdown_on_code_change", False)) else "alert"
            sig = hashlib.sha1(json.dumps([(p, cur.get(p)) for p in changed]).encode()).hexdigest()[:10]
            findings.append(F(sev, f"tamper:{repo}:{sig}", f"{name}: files changed",
                              "Changed since the trusted baseline: " + ", ".join(changed)
                              + ("\n(Workflow files changed - these can run code with your secrets.)" if wf_changed else ""),
                              FIX_HACK if sev == "high" else
                              ["Did YOU edit these files? If yes: supervisor repo > Actions > Bot supervisor > "
                               "Run workflow > mode 'accept'.",
                               "If you did NOT: treat it as a hack - see the lockdown steps (change password, "
                               "check Commits, revoke tokens)."], f"https://github.com/{repo}/commits"))

    # 4. suspicious runs
    for r in runs:
        wid = r["workflow_id"]
        if wid in dyn_ids:
            continue
        if wid not in allowed_ids:
            findings.append(F("high", f"rogue-run:{repo}:{r['id']}", f"{name}: unknown workflow ran",
                              f"Run #{r['run_number']} of '{r['name']}' is not one of your workflows.",
                              FIX_HACK, r["html_url"]))
        elif r["event"] not in SELF_RUN_EVENTS:
            findings.append(F("high", f"event:{repo}:{r['id']}", f"{name}: run started by unexpected trigger",
                              f"Run #{r['run_number']} was triggered by '{r['event']}' (expected schedule/manual).",
                              FIX_HACK, r["html_url"]))
        elif r["event"] == "workflow_dispatch":
            who = ((r.get("triggering_actor") or r.get("actor") or {}).get("login") or "").lower()
            if who and who not in actors:
                findings.append(F("high", f"actor:{repo}:{r['id']}", f"{name}: manual run by someone else",
                                  f"Run #{r['run_number']} was started by '{who}'.", FIX_HACK, r["html_url"]))
    recent = [r for r in runs if now - ts(r["created_at"]) <= timedelta(minutes=60)]
    limit = bot.get("max_runs_per_hour", 25)
    if len(recent) > limit:
        findings.append(F("high", f"burst:{repo}:{int(now.timestamp() // 3600)}", f"{name}: too many runs",
                          f"{len(recent)} runs in the last hour (limit {limit}). Could be abuse or a loop.",
                          FIX_HACK, repo_url))
    max_min = bot.get("max_run_minutes", 45)
    for r in runs:
        if r["status"] == "completed" and r.get("run_started_at"):
            mins = (ts(r["updated_at"]) - ts(r["run_started_at"])).total_seconds() / 60
            if mins > max_min:
                findings.append(F("alert", f"slow:{repo}:{r['id']}", f"{name}: run took too long",
                                  f"Run #{r['run_number']} took {mins:.0f} min (limit {max_min}).",
                                  ["Open the run and look at which step is slow.", "Paste what you see to Claude."],
                                  r["html_url"]))

    # 5. failures (retry once automatically) and staleness
    max_age = timedelta(hours=bot.get("max_age_hours", 4))
    for p in allowed:
        w = by_path.get(p)
        if not w or locked or w["state"] != "active":
            continue
        wruns = sorted((r for r in runs if r["workflow_id"] == w["id"]), key=lambda r: r["created_at"], reverse=True)
        if wruns:
            head = wruns[0]
            if head["status"] == "completed" and head["conclusion"] in FAIL:
                if head["run_attempt"] == 1 and head["id"] not in rs["retried"]:
                    rerun_failed(repo, head["id"])
                    if ACT:
                        rs["retried"] = (rs["retried"] + [head["id"]])[-50:]
                    auto.append(f"{name}: run #{head['run_number']} failed - retried automatically once")
                else:
                    streak = 0
                    for r in wruns:
                        if r["status"] == "completed" and r["conclusion"] in FAIL:
                            streak += 1
                        elif r["status"] == "completed":
                            break
                    findings.append(F("alert", f"fail:{repo}:{head['id']}:{head['run_attempt']}",
                                      f"{name}: bot is failing",
                                      f"Run #{head['run_number']} failed ({head['conclusion']}) even after retry. "
                                      f"{streak} failure(s) in a row.", FIX_FAILED, head["html_url"]))
        age = (now - ts(wruns[0]["created_at"])) if wruns else timedelta(days=99)
        if age > max_age:
            last = f"{age.total_seconds() / 3600:.1f}h ago" if wruns else "none in the last 26h"
            findings.append(F("alert", f"stale:{repo}:{p}:{int(now.timestamp() // (6 * 3600))}",
                              f"{name}: bot hasn't run", f"Last run: {last} (expected within "
                              f"{bot.get('max_age_hours', 4)}h).", FIX_STALE, repo_url))
    return {"findings": findings, "auto": auto, "wfs": wfs, "runs": runs, "locked": locked}


def lockdown(bot, wfs, runs, st, now, reasons):
    repo = bot["repo"]
    for w in wfs:
        if w["state"] == "active":
            try:
                disable_wf(repo, w["id"])
            except ApiError as e:
                print("   disable failed:", e)
    for r in runs:
        if r["status"] in ("queued", "in_progress", "waiting"):
            try:
                cancel_run(repo, r["id"])
            except ApiError:
                pass
    if ACT:
        st["shutdown"][repo] = {"time": now.isoformat(), "reasons": reasons[:5]}


# ------------------------------------------------------------------ main
def load_state():
    base = {"repos": {}, "shutdown": {}, "alerted": {}, "autolog": [], "last_report": ""}
    if STATE_FILE.exists():
        base.update(json.loads(STATE_FILE.read_text()))
    return base


def save_state(st):
    if ACT:
        STATE_FILE.write_text(json.dumps(st, indent=1, sort_keys=True))


def fmt_age(td):
    m = int(td.total_seconds() // 60)
    return f"{m}m ago" if m < 120 else f"{m // 60}h ago"


def main():
    global ACT
    mode = next((a[2:] for a in sys.argv[1:] if a.startswith("--")), "monitor")
    ACT = mode != "status"
    st, now = load_state(), now_utc()
    bots = CONFIG["bots"]

    if not TOKEN:
        notify("Supervisor: token missing", "GH_TOKEN secret is empty. Add MONITOR_TOKEN in the supervisor repo "
               "(Settings > Secrets and variables > Actions).", "urgent", "rotating_light")
        sys.exit(1)

    if mode in ("accept", "recover"):
        for b in bots:
            st["repos"].setdefault(b["repo"], {"baseline": {}, "retried": []})["baseline"] = \
                file_shas(b["repo"], b.get("watch_files", []))
        notify("Supervisor: baseline updated", "Current files of all bots are now trusted.", "default", "white_check_mark")
    if mode in ("reenable", "recover"):
        for b in bots:
            if b["repo"] in st["shutdown"]:
                for w in list_workflows(b["repo"]):
                    if w["path"] in b["workflows"] and w["state"] != "active":
                        enable_wf(b["repo"], w["id"])
                del st["shutdown"][b["repo"]]
                notify("Supervisor: bot re-enabled", f"{b['name']} is running again.", "default", "white_check_mark")
    if mode in ("accept", "reenable", "recover"):
        save_state(st)
        return

    report_lines, problems, all_auto = [], 0, []
    for b in bots:
        try:
            res = check_repo(b, st, now)
        except ApiError as e:
            if e.status == 401:
                notify("Supervisor: token rejected", "GitHub rejected the token (expired or revoked).\n"
                       + steps(["GitHub > Settings > Developer settings > Fine-grained tokens > make a new one "
                                "(Actions: read+write, Contents: read).",
                                "Supervisor repo > Settings > Secrets > update MONITOR_TOKEN."]), "urgent", "key")
                sys.exit(1)
            key = f"apierr:{b['repo']}:{int(now.timestamp() // (6 * 3600))}"
            if key not in st["alerted"]:
                st["alerted"][key] = now.isoformat()
                notify(f"Supervisor can't check {b['name']}",
                       f"{e}\n\n" + steps(["Check the repo name in config.json is spelled exactly right.",
                                           "Make sure your token has access to this repo (token settings > "
                                           "Repository access).",
                                           "If GitHub is down, this fixes itself."]), "high", "warning")
            report_lines.append(f"? {b['name']}: could not check ({e.status})")
            problems += 1
            continue
        fs, auto, runs, wfs = res["findings"], res["auto"], res["runs"], res["wfs"]
        all_auto += auto
        highs = [f for f in fs if f["sev"] == "high"]
        if highs and not res["locked"]:
            if CONFIG.get("auto_shutdown", True):
                lockdown(b, wfs, runs, st, now, [h["title"] + " - " + h["detail"] for h in highs])
            fresh = [h for h in highs if h["key"] not in st["alerted"]]
            if fresh:
                body = "\n".join(f"- {h['detail']}" for h in fresh[:5])
                state_line = ("BOT STOPPED: all its workflows were disabled and running jobs cancelled."
                              if CONFIG.get("auto_shutdown", True) and ACT else
                              "Auto-shutdown is OFF - the bot is still running.")
                notify(f"SECURITY: {b['name']} locked down" if CONFIG.get("auto_shutdown", True)
                       else f"SECURITY WARNING: {b['name']}", f"{state_line}\n\n{body}\n\nWHAT TO DO:\n{steps(FIX_HACK)}",
                       "urgent", "rotating_light", fresh[0]["url"])
            for h in highs:
                st["alerted"][h["key"]] = now.isoformat()
        for f in fs:
            if f["sev"] != "alert" or f["key"] in st["alerted"]:
                continue
            st["alerted"][f["key"]] = now.isoformat()
            notify(f["title"], f"{f['detail']}\n\nWHAT TO DO:\n{steps(f['fix'])}", "high", "warning", f["url"])
        # report line
        locked = b["repo"] in st["shutdown"]
        bad = [f for f in fs if f["sev"] in ("alert", "high")]
        icon = "LOCKED DOWN" if locked else ("PROBLEM" if bad else "OK")
        problems += 1 if (locked or bad) else 0
        latest = max((ts(r["created_at"]) for r in runs), default=None)
        fails = sum(1 for r in runs if r["conclusion"] in FAIL)
        report_lines.append(f"[{icon}] {b['name']}: last run {fmt_age(now - latest) if latest else 'none in 26h'}, "
                            f"{len(runs)} runs/26h, {fails} failed")

    if _token_expiry:
        try:
            left = (datetime.strptime(_token_expiry.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
                    .replace(tzinfo=timezone.utc) - now).days
            report_lines.append(f"Token expires in {left} days")
            key = f"token:{now.strftime('%G%V')}"
            if left < 14 and key not in st["alerted"]:
                st["alerted"][key] = now.isoformat()
                notify("Supervisor token expires soon", f"Only {left} days left.\n" + steps(
                    ["GitHub > Settings > Developer settings > Fine-grained tokens > Regenerate (or make a new one).",
                     "Supervisor repo > Settings > Secrets > update MONITOR_TOKEN."]), "high", "key")
        except ValueError:
            pass

    st["autolog"] = (st["autolog"] + [f"{now:%m-%d %H:%M} {a}" for a in all_auto])[-30:]
    if mode == "report":
        log = [l for l in st["autolog"]]
        body = "\n".join(report_lines) + ("\n\nAuto-fixes since last report:\n" + "\n".join(log) if log else "")
        notify("Bot supervisor daily report - " + ("all healthy" if not problems else f"{problems} need attention"),
               body, "default" if not problems else "high", "white_check_mark" if not problems else "warning")
        st["autolog"], st["last_report"] = [], now.strftime("%Y-%m-%d")
    else:
        print("\n".join(report_lines))
    st["alerted"] = {k: v for k, v in st["alerted"].items() if now - ts(v) < timedelta(days=14)}
    save_state(st)


if __name__ == "__main__":
    main()
