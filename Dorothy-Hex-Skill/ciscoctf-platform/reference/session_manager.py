#!/usr/bin/env python3
"""CiscoCTF Session Manager - paste session_id ONCE, use forever."""

import json, os, sys, subprocess, re, time
from datetime import datetime

CONFIG_FILE = os.path.expanduser("~/.ciscoctf_config.json")
LOG_FILE = os.path.expanduser("~/.ciscoctf_log.json")
ENC = "%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9"
BASE = "https://netacad.ciscoctf.io/" + ENC

def save_session(sid, csess):
    sid = sid.strip().strip('"').strip("'")
    if sid.startswith("session_id="):
        sid = sid[len("session_id="):].strip().strip('"').strip("'")
    cfg = {"session_id": sid, "csessxptim": csess}
    # Preserve telegram config if exists
    old = load_session_raw()
    if old and "telegram" in old:
        cfg["telegram"] = old["telegram"]
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f)
    print("Saved session to " + CONFIG_FILE)

def load_session_raw():
    if not os.path.exists(CONFIG_FILE): return None
    with open(CONFIG_FILE) as f:
        return json.load(f)

def load_session():
    c = load_session_raw()
    if not c:
        print("No saved session. Run: python3 session_manager.py save")
        sys.exit(1)
    return c

def get_cookie(session):
    return 'csessxptim=' + session["csessxptim"] + '; session_id="' + session["session_id"] + '"'

def curl_get(path, cookie=None):
    if not cookie: cookie = get_cookie(load_session())
    r = subprocess.run(["curl", "-s", "-H", "Cookie: " + cookie, BASE + path],
                       capture_output=True, text=True)
    return r.stdout

def curl_post(path, data, cookie=None, referer=None):
    session = load_session()
    if not cookie: cookie = get_cookie(session)
    args = ["curl", "-s", "-H", "Cookie: " + cookie]
    if referer: args += ["-H", "Referer: " + referer]
    for k, v in data.items():
        args += ["-d", k + "=" + v]
    args.append(BASE + path)
    r = subprocess.run(args, capture_output=True, text=True)
    return r.stdout

def refresh_xsrf(cookie=None):
    html = curl_get("/user/event/select", cookie)
    m = re.search(r'name="_xsrf" value="([^"]+)"', html)
    return m.group(1) if m else None

def get_missions_page(mission_uuid, cookie=None):
    return curl_get("/user/missions/missions?uuid=" + mission_uuid, cookie)

def submit_flag(flag_uuid, answer, mission_uuid, xsrf=None, cookie=None):
    session = load_session()
    if not cookie: cookie = get_cookie(session)
    if not xsrf: xsrf = refresh_xsrf(cookie)
    if not xsrf: return "ERROR: no xsrf"
    c = "csessxptim=" + session["csessxptim"] + "; _xsrf=" + xsrf + '; session_id="' + session["session_id"] + '"'
    return curl_post("/user/missions/capture",
        {"_xsrf": xsrf, "uuid": flag_uuid, "token": answer},
        c, BASE + "/user/missions/missions?uuid=" + mission_uuid)

def parse_flag_section(html, flag_uuid):
    """Extract question text + attempts for a specific flag UUID."""
    qtext, att = "?", "?"
    idx = html.find("border-flag-separator")
    while idx > 0:
        chunk = html[idx:idx+3000]
        if flag_uuid in chunk:
            md = re.search(r'<div class="markdown">(.*?)</div>', chunk, re.DOTALL)
            if md: qtext = re.sub(r'<[^>]+>', '', md.group(1)).strip()[:200]
            at = re.search(r'(\d+)/5\s*<br>\s*<span class="smalltext">Attempts', chunk)
            if at: att = at.group(1)
            break
        idx = html.find("border-flag-separator", idx + 1)
    return qtext, att

def extract_status(html):
    results = {}
    sections = re.split(r'<div class="row border-flag-separator', html)
    for s in sections:
        q = re.search(r'Question (\d+)', s)
        uuid = re.search(r'id="([a-f0-9-]+)"', s)
        attempts = re.search(r'(\d+)/5\s*<br>\s*<span class="smalltext">Attempts', s)
        completed = bool(re.search(r'check-circle', s))
        if q and uuid:
            results[int(q.group(1))] = {
                "uuid": uuid.group(1),
                "attempts": attempts.group(1) if attempts else "?",
                "completed": completed
            }
    return results

def scoreboard(event_code, cookie=None):
    return curl_get("/scoreboard/ajax/summary?e=" + event_code, cookie)

def list_events(cookie=None):
    html = curl_get("/user/event/select", cookie)
    events = {}
    for key in ["current_events_codes_list", "unjoined_events_codes_list", "upcoming_events_codes_list"]:
        m = re.search(r'data-' + key + '="([^"]*)"', html)
        if m and m.group(1):
            for code in m.group(1).split(","):
                status = key.replace("_events_codes_list", "").replace("_", " ")
                events[code.strip()] = status
    return events

def select_event(event_code, cookie=None):
    session = load_session()
    if not cookie: cookie = get_cookie(session)
    html = curl_get("/user/event/select", cookie)
    xsrf = re.search(r'name="_xsrf" value="([^"]+)"', html)
    if not xsrf: return "ERROR: no xsrf"
    x = xsrf.group(1)
    c = 'csessxptim=' + session["csessxptim"] + '; _xsrf=' + x + '; session_id="' + session["session_id"] + '"'
    r = subprocess.run(["curl", "-s", "-D", "/dev/null",
        "-H", "Cookie: " + c,
        "-H", "Referer: " + BASE + "/user/event/select",
        "-d", "_xsrf=" + x,
        "-d", "event_code=" + event_code,
        BASE + "/user/event/select"], capture_output=True, text=True)
    return r.stdout

def list_missions(cookie=None):
    html = curl_get("/user/event/home", cookie)
    uuids = re.findall(r'missions\?uuid=([a-f0-9-]+)', html)
    event_name = re.search(r'<h3[^>]*>(.*?)</h3>', html)
    if event_name:
        print("Event: " + re.sub(r'<[^>]+>', '', event_name.group(1)).strip())
    seen = set()
    for uid in uuids:
        if uid not in seen:
            seen.add(uid)
            m = curl_get("/user/missions/missions?uuid=" + uid, cookie)
            t = re.search(r'<title>(.*?)</title>', m)
            print("  [" + (t.group(1) if t else '?') + "] -> " + uid)

# ─── Auto-whois/DNS ───────────────────────────────────────────────

def auto_answer(question_text):
    """Detect question type and auto-answer via whois/DNS."""
    q = question_text.lower()
    
    # "When was the domain X created?" → whois creation date
    m = re.search(r'when was the domain (\S+) created', q)
    if m:
        domain = m.group(1).rstrip('?.,!;:')
        print("Auto-whois: querying " + domain + " creation date...")
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
        # Try IANA registry date first
        d = re.search(r'Created:\s*(\d{4}-\d{2}-\d{2})', r.stdout, re.IGNORECASE)
        if d: return d.group(1), "whois (IANA)"
        d = re.search(r'Creation Date:\s*(\d{4}-\d{2}-\d{2})', r.stdout, re.IGNORECASE)
        if d: return d.group(1), "whois (RFC)"
        return None, None
    
    # "What is Registrar IANA ID of X?" → whois
    m = re.search(r'registrar iana id\s+of\s+(\S+)', q)
    if m:
        domain = m.group(1).rstrip('?.,!;:')
        print("Auto-whois: querying " + domain + " IANA ID...")
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
        d = re.search(r'Registrar IANA ID:\s*(\d+)', r.stdout)
        if d: return d.group(1), "whois"
        return None, None
    
    # "Who is registrar for X?" → whois
    m = re.search(r'registrar\s+for\s+(?:the\s+)?domain\s+(\S+)', q)
    if m:
        domain = m.group(1).rstrip('?.,!;:')
        print("Auto-whois: querying " + domain + " registrar...")
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
        d = re.search(r'Registrar:\s*(.+)', r.stdout, re.IGNORECASE)
        if d:
            name = d.group(1).strip().rstrip(',')
            return name, "whois"
        return None, None

    # "How many nameservers does X have?" → dig NS
    m = re.search(r'how many nameservers\s+(?:does\s+)?(\S+)', q)
    if m:
        domain = m.group(1).rstrip('?.,!;:')
        print("Auto-DNS: querying NS records for " + domain + "...")
        r = subprocess.run(["dig", "+short", "NS", domain], capture_output=True, text=True, timeout=15)
        count = len([l for l in r.stdout.split('\n') if l.strip()])
        return str(count), "dns"
    
    return None, None

# ─── Submission log ────────────────────────────────────────────────

def log_submission(flag_uuid, question, answer, result, points=0):
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            try: logs = json.load(f)
            except: logs = []
    logs.append({
        "timestamp": datetime.now().isoformat(),
        "flag_uuid": flag_uuid,
        "question": question[:100],
        "answer": answer,
        "result": result,
        "points": points
    })
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def show_log(limit=20):
    if not os.path.exists(LOG_FILE):
        print("No submission log yet.")
        return
    with open(LOG_FILE) as f:
        logs = json.load(f)
    if not logs:
        print("No submissions logged.")
        return
    total_pts = sum(l.get("points", 0) for l in logs)
    success = sum(1 for l in logs if l["result"] == "SUCCESS")
    failed = sum(1 for l in logs if l["result"] == "INCORRECT")
    print("Last " + str(min(limit, len(logs))) + "/" + str(len(logs)) + " submissions:")
    print("  Total: " + str(len(logs)) + " | SUCCESS: " + str(success) + " | INCORRECT: " + str(failed) + " | Points: " + str(total_pts))
    print("─" * 50)
    for log in reversed(logs[-limit:]):
        t = log["timestamp"][:19]
        r = "✅" if log["result"] == "SUCCESS" else "❌" if log["result"] == "INCORRECT" else "❓"
        p = " +" + str(log["points"]) if log.get("points") else ""
        print("  " + r + " " + t + " | " + log["answer"] + p + " | " + log["question"][:50])

# ─── Telegram ──────────────────────────────────────────────────────

TELEGRAM_API = "https://api.telegram.org/bot"

def telegram_send(text, parse_mode=None):
    cfg = load_session_raw()
    if not cfg or "telegram" not in cfg:
        print("No Telegram config. Set it with: python3 session_manager.py tg-set <token> <chat_id>")
        return False
    tk = cfg["telegram"]["token"]
    cid = cfg["telegram"]["chat_id"]
    data = {"chat_id": cid, "text": text}
    if parse_mode: data["parse_mode"] = parse_mode
    r = subprocess.run(["curl", "-s", "-X", "POST",
        TELEGRAM_API + tk + "/sendMessage",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(data)], capture_output=True, text=True)
    return "ok" in r.stdout.lower()

def telegram_keyboard(text, buttons):
    """Send message with inline keyboard. buttons = [['label1', 'callback1'], ...]"""
    cfg = load_session_raw()
    if not cfg or "telegram" not in cfg: return False
    rows = []
    for row in buttons:
        rows.append([{"text": b[0], "callback_data": b[1]} for b in row])
    kb = {"inline_keyboard": rows}
    payload = {"chat_id": cfg["telegram"]["chat_id"], "text": text, "reply_markup": kb}
    r = subprocess.run(["curl", "-s", "-X", "POST",
        TELEGRAM_API + cfg["telegram"]["token"] + "/sendMessage",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload)], capture_output=True, text=True)
    return "ok" in r.stdout.lower()

# ─── Session check ────────────────────────────────────────────────

# ─── My Score ──────────────────────────────────────────────────────

def get_my_score_html():
    """Fetch /user/settings which contains own username."""
    session = load_session()
    cookie = get_cookie(session)
    html = curl_get("/user/settings", cookie)
    # Extract username
    name = "?"
    m = re.search(r'value="([^"]+)"\s*(?:name|id)\s*=?\s*"username"', html, re.IGNORECASE)
    if not m:
        m = re.search(r'<h[1-6][^>]*>\s*(.*?)\s*</h[1-6]>', html)
        if m: name = re.sub(r'<[^>]+>', '', m.group(1)).strip()
    else:
        name = m.group(1)
    if name == "?":
        # Try from event home
        html2 = curl_get("/user/event/home", cookie)
        m = re.search(r'Welcome[^,]*,\s*(\S+)', html2, re.IGNORECASE)
        if m: name = m.group(1)
    return name, html

def parse_my_rank(event_code, username, cookie):
    """Parse leaderboard to find own rank + score."""
    html = curl_get("/scoreboard/ajax/summary?e=" + event_code, cookie)
    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL)
    for row in rows:
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        if len(cells) >= 3:
            rank = re.sub(r'<[^>]+>', '', cells[0]).strip()
            name = re.sub(r'<[^>]+>', '', cells[1]).strip()
            score = re.sub(r'<[^>]+>', '', cells[2]).strip()
            if name.lower() == username.lower():
                return rank, score, len(rows)
    return None, None, len(rows)

def parse_my_score_from_event_home(event_code, cookie):
    """Parse event home for score and flags captured summary."""
    html = curl_get("/user/event/home", cookie)
    data = {"score": "?", "captured": "?", "total": "?", "rank": "?", "players": "?"}

    # Score patterns
    m = re.search(r'(\d+)\s*/\s*(\d+)\s*flags?\s*captured', html, re.IGNORECASE)
    if m:
        data["captured"] = m.group(1)
        data["total"] = m.group(2)
    m = re.search(r'(\d+)\s*points?\s*(?:/\s*\d+)?', html, re.IGNORECASE)
    if m: data["score"] = m.group(1)

    # Also try score in summary
    summaries = re.findall(r'<div[^>]*class="[^"]*summary[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
    for s in summaries:
        m = re.search(r'(\d+)', s)
        if m and data["score"] == "?":
            data["score"] = m.group(1)

    # Try leaderboard for rank
    name, _ = get_my_score_html()
    if name != "?":
        rank, score, players = parse_my_rank(event_code, name, cookie)
        if rank:
            data["rank"] = rank
            data["players"] = str(players)
            if score:
                data["score"] = score

    return data

def show_myscore(event_code):
    """Display own score, rank, and per-flag status."""
    session = load_session()
    cookie = get_cookie(session)

    name, _ = get_my_score_html()
    print("=" * 50)
    print("Player: " + name)
    print("Event:  " + event_code)
    print("=" * 50)

    # Score from event home
    data = parse_my_score_from_event_home(event_code, cookie)
    if data["rank"] != "?":
        print("Rank:   #" + data["rank"] + " / " + data["players"])
    print("Score:  " + data["score"] + " pts")
    if data["captured"] != "?":
        print("Flags:  " + data["captured"] + " / " + data["total"] + " captured")
    print()

    # Get per-flag status
    html = curl_get("/user/event/home", cookie)
    muids = re.findall(r'missions\?uuid=([a-f0-9-]+)', html)
    if muids:
        mid = muids[0]  # active mission
        mhtml = curl_get("/user/missions/missions?uuid=" + mid, cookie)
        status = extract_status(mhtml)
        print("Flags:")
        for q, info in sorted(status.items()):
            icon = "✅" if info["completed"] else "⬜"
            print("  Q" + str(q) + ": " + icon + " " + info["attempts"] + "/5")
    print()

    # Try report card
    myreport_html = curl_get("/myreport?e=" + event_code + "&uuid=" + (mid if muids else ""), cookie)
    captured_flags = re.findall(r'(Captured|Not Captured)(?:\s*Flag\s*(\d+))?', myreport_html)
    if captured_flags:
        print("Report Card:")
        for status, num in captured_flags:
            icon = "✅" if status == "Captured" else "⬜"
            print("  " + icon + " " + status + (" (Flag " + num + ")" if num else ""))

def check_session():
    """Verify session is still valid by accessing a protected page."""
    session = load_session()
    cookie = get_cookie(session)
    r = subprocess.run(["curl", "-s", "-D", "-", "-H", "Cookie: " + cookie,
        BASE + "/"], capture_output=True, text=True)
    # Check for location header
    loc = re.search(r'location:\s*(\S+)', r.stdout, re.IGNORECASE)
    if loc:
        path = loc.group(1)
        if "login" in path:
            print("❌ Session EXPIRED. Run: python3 session_manager.py save")
            return False
        elif "event/select" in path or "event/home" in path:
            print("✅ Session valid")
            # Show session info
            print("  session_id: ..." + session["session_id"][-10:])
            print("  csessxptim: " + str(session["csessxptim"]))
            # Check expiry
            try: remaining = int(session["csessxptim"]) - int(time.time())
            except: remaining = 0
            if remaining > 3600:
                print("  expires in: " + str(remaining // 60) + " min")
            elif remaining > 0:
                print("⚠️  expires in: " + str(remaining // 60) + " min! Save new session soon.")
            return True
    print("❌ Session invalid (unexpected response)")
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Session:      save | check")
        print("  Events:       events | select <code> | missions")
        print("  Flags:        status <mission_uuid>")
        print("  My Score:     myscore <event_code>")
        print("  Report Card:  myreport <event_code> <mission_uuid>")
        print("  Submit:       submit <flag_uuid> <answer> <mission_uuid>")
        print("  Auto-submit:  auto <flag_uuid> <mission_uuid>  (whois/DNS detection)")
        print("  Batch:        batch <flag_uuid>=<answer> <flag_uuid>=<answer> ...")
        print("  Log:          log [limit]")
        print("  Telegram:     tg-set <token> <chat_id> | tg-send <text>")
        print("  Scoreboard:   lb <event_code>")
        print("  XSRF:         xsrf")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "save":
        print("Paste session_id from F12 → Application → Cookies → netacad.ciscoctf.io")
        sid = input("session_id: ").strip()
        csess = input("csessxptim (or Enter for default): ").strip() or "1782335498"
        save_session(sid, csess)

    elif cmd == "check":
        check_session()

    elif cmd == "xsrf":
        print("XSRF: " + (refresh_xsrf() or "ERROR"))

    elif cmd == "events":
        for code, status in list_events().items():
            print("  [" + status + "] " + code)

    elif cmd == "select":
        r = select_event(sys.argv[2])
        if "location" not in r:
            print("Event " + sys.argv[2] + " selected!")
        else:
            print("Response: " + str(len(r)) + " bytes")

    elif cmd == "myscore":
        ec = sys.argv[2] if len(sys.argv) > 2 else "XFNDF0"
        show_myscore(ec)

    elif cmd == "myreport":
        if len(sys.argv) < 4: print("Usage: myreport <event_code> <mission_uuid>"); sys.exit(1)
        html = curl_get("/myreport?e=" + sys.argv[2] + "&uuid=" + sys.argv[3])
        captured = re.findall(r'(Captured|Not Captured)(?:\s*Flag\s*(\d+))?', html)
        print("Report Card:")
        for status, num in captured:
            icon = "✅" if status == "Captured" else "⬜"
            print("  " + icon + " " + status + (" (Flag " + num + ")" if num else ""))

    elif cmd == "missions":
        list_missions()

    elif cmd == "status":
        html = get_missions_page(sys.argv[2])
        status = extract_status(html)
        for q, info in sorted(status.items()):
            icon = "✅" if info["completed"] else "⬜"
            print("Q" + str(q) + ": " + icon + " " + info["attempts"] + "/5  uuid=" + info["uuid"])

    elif cmd == "mission":
        html = get_missions_page(sys.argv[2])
        for q, info in sorted(extract_status(html).items()):
            icon = "✅" if info["completed"] else "⬜"
            print("Q" + str(q) + ": " + icon + " attempts=" + info["attempts"] + "/5 uuid=" + info["uuid"])

    elif cmd == "submit":
        if len(sys.argv) < 5: print("Usage: submit <flag_uuid> <answer> <mission_uuid>"); sys.exit(1)
        fuuid, answer, muid = sys.argv[2], sys.argv[3], sys.argv[4]
        mhtml = get_missions_page(muid)
        qtext, att = parse_flag_section(mhtml, fuuid)
        att_int = int(att) if att.isdigit() else 0
        remaining = 5 - att_int

        print("=" * 50)
        print("Question: " + qtext)
        print("Attempts: " + att + "/5 used (" + str(remaining) + " remaining)")
        print("Answer:   " + answer)
        print("=" * 50)

        if remaining <= 0:
            print("No attempts remaining. Cannot submit."); sys.exit(1)
        elif remaining <= 2:
            if input("Only " + str(remaining) + " left. Submit? (y/N): ").strip().lower() != 'y':
                print("Cancelled."); sys.exit(0)

        time.sleep(2)
        html = submit_flag(fuuid, answer, muid)
        if re.search(r'alert-success.*?SUCCESS', html, re.DOTALL):
            result = "SUCCESS"
            points = 20
        elif re.search(r'alert-danger.*?INCORRECT', html, re.DOTALL):
            result = "INCORRECT"
            points = 0
        else:
            result = "UNKNOWN"; points = 0
        print("Result: " + result)
        log_submission(fuuid, qtext[:100], answer, result, points)
        # Telegram notify
        icon = "✅" if result == "SUCCESS" else "❌"
        points_str = " [+" + str(points) + "pts]" if points else ""
        telegram_send(icon + " " + result + " - " + qtext[:60] + " → " + answer + points_str)

    elif cmd == "auto":
        """Auto-detect question via whois/DNS and submit."""
        fuuid, muid = sys.argv[2], sys.argv[3]
        mhtml = get_missions_page(muid)
        qtext, att = parse_flag_section(mhtml, fuuid)
        if qtext == "?":
            print("Could not read question text."); sys.exit(1)
        print("Question: " + qtext)
        answer, source = auto_answer(qtext)
        if answer is None:
            print("Cannot auto-answer this question. Use 'submit' manually.")
            sys.exit(1)
        print("Auto-answer (" + source + "): " + answer)
        # Verify with user (if remaining <= 2)
        att_int = int(att) if att.isdigit() else 0
        remaining = 5 - att_int
        if remaining <= 2:
            if input("Only " + str(remaining) + " left. Submit? (y/N): ").strip().lower() != 'y':
                print("Cancelled."); sys.exit(0)
        time.sleep(2)
        html = submit_flag(fuuid, answer, muid)
        if re.search(r'alert-success.*?SUCCESS', html, re.DOTALL):
            result = "SUCCESS"; points = 20
        elif re.search(r'alert-danger.*?INCORRECT', html, re.DOTALL):
            result = "INCORRECT"; points = 0
        else:
            result = "UNKNOWN"; points = 0
        print("Result: " + result)
        log_submission(fuuid, qtext[:100], answer, result, points)
        telegram_send(("✅" if result == "SUCCESS" else "❌") + " [Auto] " + qtext[:40] + " → " + answer + (" [+" + str(points) + "pts]" if points else ""))

    elif cmd == "batch":
        """Submit multiple flags: batch <fuuid>=<answer> <fuuid>=<answer> ..."""
        if len(sys.argv) < 3: print("Usage: batch <fuuid>=<ans> [<fuuid>=<ans> ...]"); sys.exit(1)
        muid = "dba5c34f-8eff-46b8-b857-a0daf1eb690b"
        # Check if last arg looks like a mission UUID
        if re.match(r'^[a-f0-9-]{36}$', sys.argv[-1]) and '=' not in sys.argv[-1]:
            muid = sys.argv[-1]
            pairs = sys.argv[2:-1]
        else:
            pairs = sys.argv[2:]
        mhtml = get_missions_page(muid)
        results = []
        for pair in pairs:
            if '=' not in pair: continue
            fuuid, answer = pair.split('=', 1)
            qtext, att = parse_flag_section(mhtml, fuuid)
            print("[" + qtext[:40] + "...] → " + answer)
            time.sleep(2)
            html = submit_flag(fuuid, answer, muid)
            if re.search(r'alert-success.*?SUCCESS', html, re.DOTALL):
                r = "SUCCESS"; p = 20
            elif re.search(r'alert-danger.*?INCORRECT', html, re.DOTALL):
                r = "INCORRECT"; p = 0
            else:
                r = "UNKNOWN"; p = 0
            results.append((qtext[:60], answer, r, p))
            log_submission(fuuid, qtext[:100], answer, r, p)
        print("═" * 40)
        for q, a, r, p in results:
            icon = "✅" if r == "SUCCESS" else "❌"
            print("  " + icon + " " + q + " → " + a + " = " + r + (" +" + str(p) + "pts" if p else ""))

    elif cmd == "log":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        show_log(limit)

    elif cmd == "tg-set":
        """Save Telegram bot token + chat_id."""
        if len(sys.argv) < 4: print("Usage: tg-set <token> <chat_id>"); sys.exit(1)
        cfg = load_session_raw() or {"session_id": "", "csessxptim": ""}
        cfg["telegram"] = {"token": sys.argv[2], "chat_id": sys.argv[3]}
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f)
        print("Saved Telegram config. Testing...")
        if telegram_send("✅ CiscoCTF Bot connected!\nUse commands:\n/status - flag status\n/scoreboard - leaderboard\n/log - submission log"):
            print("✅ Telegram connected!")
        else:
            print("❌ Telegram test failed. Check token/chat_id.")

    elif cmd == "tg-send":
        if len(sys.argv) < 3: print("Usage: tg-send <text>"); sys.exit(1)
        text = " ".join(sys.argv[2:])
        if telegram_send(text):
            print("✅ Sent")
        else:
            print("❌ Failed")

    elif cmd == "lb":
        ec = sys.argv[2] if len(sys.argv) > 2 else "XFNDF0"
        html = scoreboard(ec)
        print("Leaderboard: " + str(len(html)) + " bytes")
        # Extract player count
        count = len(re.findall(r'<tr', html))
        print("Players: ~" + str(count))
