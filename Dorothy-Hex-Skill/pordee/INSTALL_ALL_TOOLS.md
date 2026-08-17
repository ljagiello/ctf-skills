# ติดตั้ง pordee (พอดี) สำหรับทุก AI Coding Tools

---

## 🟢 Zed (Zed AI / Zed Agent)

ติดตั้งแล้ว! Skill อยู่ที่ `~/.agents/skills/pordee/SKILL.md`

**วิธีใช้ใน Zed:**

```
พูดสั้นๆ  → เปิดโหมดกระชับ
พูดปกติ   → ปิดโหมด
ขยายความ  → ขอรายละเอียด
```

---

## 🟢 Claude Code (Anthropic)

### วิธีที่ 1 — Plugin Marketplace (แนะนำ)

```bash
claude plugin marketplace add kerlos/pordee
claude plugin install pordee@pordee
```

### วิธีที่ 2 — Manual config

เพิ่มใน `~/.claude/settings.json`:

```json
{
  "additionalContext": {
    "files": ["~/.agents/skills/pordee/SKILL.md"]
  }
}
```

หรือใช้ `CLAUDE_GLOBAL_INSTRUCTIONS`:

```bash
export CLAUDE_GLOBAL_INSTRUCTIONS="$HOME/.agents/skills/pordee/SKILL.md"
```

---

## 🟢 Cursor

เพิ่มใน `.cursorrules` ของโปรเจค:

```txt
Follow pordee rules: ตัดคำสุภาพ (ครับ/ค่ะ/นะคะ), ลังเล (อาจจะ/น่าจะ), filler ตอบสั้น technical term ใช้ Eng.
```

หรือใช้ Cursor Rules: Settings → Rules → paste จาก `~/.agents/skills/pordee/SKILL.md`

---

## 🟢 GitHub Copilot / Codex (VS Code)

เพิ่มใน `.github/copilot-instructions.md`:

```markdown
## pordee mode (Thai terse mode)

When user writes in Thai, respond in terse Thai:
- Drop polite particles (ครับ/ค่ะ/นะคะ)
- Drop hedging (อาจจะ/น่าจะ/จริงๆแล้ว)
- Drop filler (ก็/แบบว่า/เอ่อ)
- Keep technical English terms as-is
- Fragments OK
- Use short synonyms (ดู→ตรวจสอบ, แก้→ทำการแก้ไข)
```

---

## 🟢 OpenCode

OpenCode รองรับ system prompt จาก config:

```bash
# วิธีที่ 1: CLI flag
opencode --system-prompt "$(cat ~/.agents/skills/pordee/SKILL.md)"

# วิธีที่ 2: ใช้ OPENCODE_SYSTEM_PROMPT env
export OPENCODE_SYSTEM_PROMPT="$HOME/.agents/skills/pordee/SKILL.md"
```

---

## 🟢 Mimo

Mimo รองรับ `.mimo/config.json`:

```bash
mkdir -p ~/.mimo
```

เพิ่มใน `~/.mimo/config.json`:

```json
{
  "customInstructions": "~/.agents/skills/pordee/SKILL.md"
}
```

---

## 🟢 Windsurf / Codeium

`.windsurfrules` ที่ root โปรเจค:

```txt
[pordee] ตอบสั้น technical ไทย ตัดครับ/ค่ะ/อาจจะ/น่าจะ เก็บ Eng term ไว้
```

---

## ✅ สรุปที่ติดตั้ง

| Tool | Status | วิธีใช้ |
|------|--------|--------|
| **Zed** (Agent) | ✅ ติดตั้งแล้ว | `พูดสั้นๆ` / `พอดี` |
| **Claude Code** | ✅ Plugin available | `/pordee` หรือ `พอดี` |
| **Cursor** | ใช้ `.cursorrules` | วางกฏจาก SKILL.md |
| **Copilot/Codex** | `.github/copilot-instructions.md` | วางกฏ |
| **OpenCode** | CLI flag / env | `--system-prompt` |
| **Mimo** | `.mimo/config.json` | customInstructions |
| **Windsurf** | `.windsurfrules` | วางกฏ |
