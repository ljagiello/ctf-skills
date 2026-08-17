#!/usr/bin/env python3
"""CiscoCTF Telegram Bot — runs in background, responds to /commands."""

import json, os, sys, subprocess, re, time, threading

CONFIG_FILE = os.path.expanduser("~/.ciscoctf_config.json")
ENC = "%F0%9F%8F%86%E2%9A%A1%F0%9F%9A%A9"
BASE = "https://netacad.ciscoctf.io/" + ENC
LOG_FILE = os.path.expanduser("~/.ciscoctf_log.json")

def load_cfg():
    if not os.path.exists(CONFIG_FILE): return None
    with open(CONFIG_FILE) as f:
        return json.load(f)

def tg_api(method, payload):
    cfg = load_cfg()
    if not cfg or "telegram" not in cfg: return None
    r = subprocess.run(["curl", "-s", "-X", "POST",
        "https://api.telegram.org/bot" + cfg["telegram"]["token"] + "/" + method,
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload)], capture_output=True, text=True)
    return json.loads(r.stdout) if r.stdout else None

def get_cookie(session):
    return 'csessxptim=' + session["csessxptim"] + '; session_id="' + session["session_id"] + '"'

def curl_get(path):
    cfg = load_cfg()
    if not cfg: return ""
    r = subprocess.run(["curl", "-s", "-H", "Cookie: " + get_cookie(cfg), BASE + path],
                       capture_output=True, text=True)
    return r.stdout

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
                "uuid": uuid.group(1), "attempts": attempts.group(1) if attempts else "?",
                "completed": completed
            }
    return results

def get_questions(mission_uuid):
    html = curl_get("/user/missions/missions?uuid=" + mission_uuid)
    status = extract_status(html)
    sections = re.split(r'border-flag-separator', html)
    texts = {}
    for s in sections:
        q = re.search(r'Question (\d+)', s)
        uuid = re.search(r'id="([a-f0-9-]+)"', s)
        md = re.search(r'<div class="markdown">(.*?)</div>', s, re.DOTALL)
        if q and uuid and md:
            txt = re.sub(r'<[^>]+>', '', md.group(1)).strip()[:100]
            texts[q.group(1)] = txt
    return status, texts

def handle_command(cmd, args, chat_id):
    cfg = load_cfg()
    if not cfg: return "No config"
    if cmd == "/start":
        return "🤖 CiscoCTF Bot ready!\n/status - flag status\n/scoreboard - leaderboard\n/log - submissions\n/questions - all question text"

    elif cmd == "/status":
        html = curl_get("/user/event/home")
        muids = re.findall(r'missions\?uuid=([a-f0-9-]+)', html)
        if not muids: return "No missions found. Select an event first."
        mid = muids[0]
        status, _ = get_questions(mid)
        lines = ["📊 Flag Status:\n"]
        for q, info in sorted(status.items()):
            icon = "✅" if info["completed"] else "⬜"
            lines.append(icon + " Q" + str(q) + ": " + info["attempts"] + "/5")
        return "\n".join(lines)

    elif cmd == "/questions":
        html = curl_get("/user/event/home")
        muids = re.findall(r'missions\?uuid=([a-f0-9-]+)', html)
        if not muids: return "No missions found."
        _, texts = get_questions(muids[0])
        lines = ["📝 Questions:\n"]
        for q, txt in sorted(texts.items()):
            lines.append("Q" + str(q) + ": " + txt)
        return "\n".join(lines)

    elif cmd == "/log":
        if not os.path.exists(LOG_FILE): return "No submission log yet."
        with open(LOG_FILE) as f:
            logs = json.load(f)
        lines = ["📋 Recent submissions:\n"]
        total = sum(l.get("points", 0) for l in logs)
        for log in reversed(logs[-5:]):
            r = "✅" if log["result"] == "SUCCESS" else "❌"
            lines.append(r + " " + log["answer"] + " → " + log["result"] + (" +" + str(log["points"]) + "pts" if log.get("points") else ""))
        lines.append("\nTotal points: " + str(total))
        return "\n".join(lines)

    elif cmd == "/scoreboard":
        html = curl_get("/scoreboard?e=XFNDF0")
        players = re.findall(r'<tr[^>]*>.*?</tr>', html, re.DOTALL)
        lines = ["🏆 Leaderboard (top 10):\n"]
        count = 0
        for row in players:
            cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
            if len(cells) >= 3 and count < 10:
                name = re.sub(r'<[^>]+>', '', cells[1]).strip()
                score = re.sub(r'<[^>]+>', '', cells[2]).strip()
                lines.append("  " + str(count + 1) + ". " + name + " - " + score)
                count += 1
        return "\n".join(lines)

    return "Unknown command. Try /status, /questions, /log, /scoreboard"

def poll_once(offset):
    result = tg_api("getUpdates", {"offset": offset, "timeout": 10})
    if not result or not result.get("result"): return offset
    for update in result["result"]:
        new_offset = update["update_id"] + 1
        if "message" in update and "text" in update["message"]:
            msg = update["message"]
            cmd = msg["text"].split()[0]
            args = msg["text"].split()[1:]
            chat_id = msg["chat"]["id"]
            reply = handle_command(cmd, args, chat_id)
            print("[" + cmd + "] from " + str(chat_id) + " → " + reply[:50])
            # Send reply in chunks (Telegram limit: 4096 chars)
            while reply:
                chunk = reply[:4000]
                reply = reply[4000:]
                tg_api("sendMessage", {"chat_id": chat_id, "text": chunk})
        elif "callback_query" in update:
            cb = update["callback_query"]
            chat_id = cb["message"]["chat"]["id"]
            data = cb["data"]
            print("[callback] " + data + " from " + str(chat_id))
            tg_api("answerCallbackQuery", {"callback_query_id": cb["id"]})
    return new_offset if "new_offset" in dir() else offset

def run_polling():
    print("🤖 CiscoCTF Telegram Bot polling...")
    offset = 0
    while True:
        try: offset = poll_once(offset)
        except Exception as e: print("Error: " + str(e))
        time.sleep(1)

if __name__ == "__main__":
    cfg = load_cfg()
    if not cfg or "telegram" not in cfg:
        print("Set Telegram first: python3 session_manager.py tg-set <token> <chat_id>")
        sys.exit(1)
    print("Starting CiscoCTF Telegram Bot. Commands:")
    print("  /status - Check flag status")
    print("  /questions - All question text")
    print("  /scoreboard - Leaderboard")
    print("  /log - Submission history")
    run_polling()
