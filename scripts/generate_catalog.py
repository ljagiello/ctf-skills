#!/usr/bin/env python3
"""Generate a static HTML skill catalog for GitHub Pages."""

import html
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "_site"

# Fallback if git remote is unavailable (e.g., in CI without full clone)
_DEFAULT_REPO_URL = "https://github.com/ljagiello/ctf-skills"


def _detect_repo_url() -> str:
    """Derive the GitHub repo URL from the git remote, with fallback."""
    try:
        url = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=REPO_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        # Normalise SSH variants → HTTPS
        if url.startswith("ssh://"):
            url = url.replace("ssh://", "https://", 1).replace("git@", "")
        elif url.startswith("git@"):
            url = url.replace("git@", "https://", 1).replace(":", "/", 1)
        url = url.removesuffix(".git")
        return url
    except (subprocess.CalledProcessError, FileNotFoundError):
        return _DEFAULT_REPO_URL


# Lazy-initialized; call _get_repo_url() instead of using directly.
_repo_url: str | None = None


def _get_repo_url() -> str:
    global _repo_url
    if _repo_url is None:
        _repo_url = _detect_repo_url()
    return _repo_url


CATEGORY_COLORS = {
    "ctf-web": "#1d76db",
    "ctf-pwn": "#d93f0b",
    "ctf-crypto": "#0e8a16",
    "ctf-reverse": "#5319e7",
    "ctf-forensics": "#006b75",
    "ctf-osint": "#fbca04",
    "ctf-malware": "#b60205",
    "ctf-misc": "#c5def5",
    "ctf-ai-ml": "#f9d0c4",
    "ctf-writeup": "#888888",
    "solve-challenge": "#555555",
}

CATEGORY_ICONS = {
    "ctf-web": "\U0001f310",
    "ctf-pwn": "\U0001f4a3",
    "ctf-crypto": "\U0001f510",
    "ctf-reverse": "\U0001f50e",
    "ctf-forensics": "\U0001f50d",
    "ctf-osint": "\U0001f30e",
    "ctf-malware": "\U0001f9a0",
    "ctf-misc": "\U0001f9e9",
    "ctf-ai-ml": "\U0001f916",
    "ctf-writeup": "\U0001f4dd",
    "solve-challenge": "\U0001f3af",
}


def parse_frontmatter(text: str) -> dict[str, str]:
    """Parse YAML frontmatter into a flat dict."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = i
            break
    if end is None:
        return {}
    result: dict[str, str] = {}
    block: str | None = None
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and ":" not in stripped[:-1]:
            block = stripped[:-1]
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip().strip('"')
        if block:
            result[f"{block}.{key}"] = value
        else:
            result[key] = value
    return result


def discover_skills() -> list[Path]:
    """Find all directories containing a SKILL.md."""
    return sorted(p.parent for p in REPO_ROOT.glob("*/SKILL.md"))


def count_techniques(skill_dir: Path) -> list[dict[str, str]]:
    """List technique files in a skill directory."""
    techniques = []
    for md in sorted(skill_dir.glob("*.md")):
        if md.name == "SKILL.md":
            continue
        name = md.stem.replace("-", " ").replace("_", " ").title()
        techniques.append({"name": name, "file": md.name})
    return techniques


def build_html(skills: list[dict]) -> str:
    """Build the full HTML catalog page."""
    total_techniques = sum(len(s["techniques"]) for s in skills)
    total_categories = len([s for s in skills if s["techniques"]])

    cards = []
    for s in skills:
        color = CATEGORY_COLORS.get(s["dir_name"], "#666")
        icon = html.escape(CATEGORY_ICONS.get(s["dir_name"], "\U0001f4c4"))
        tech_count = len(s["techniques"])
        desc = html.escape(s.get("description", ""))

        tech_list = ""
        if s["techniques"]:
            items = []
            for t in s["techniques"]:
                gh_link = f"{_get_repo_url()}/blob/main/{s['dir_name']}/{t['file']}"
                label = html.escape(t["name"])
                items.append(
                    f'<li><a href="{gh_link}" target="_blank"'
                    f' rel="noopener noreferrer">{label}</a></li>'
                )
            tech_list = f'<ul class="technique-list">{"".join(items)}</ul>'

        repo = _get_repo_url()
        skill_link = f"{repo}/blob/main/{s['dir_name']}/SKILL.md"
        cards.append(f"""
    <div class="card" style="border-top: 4px solid {color}">
      <a class="card-link" href="{skill_link}"
         target="_blank" rel="noopener noreferrer">
        <div class="card-header">
          <span class="icon">{icon}</span>
          <h2>{html.escape(s["dir_name"])}</h2>
          <span class="badge" style="background:{color}">\
{tech_count} file{"s" if tech_count != 1 else ""}</span>
        </div>
        <p class="description">{desc}</p>
      </a>
      {tech_list}
    </div>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CTF Skills Catalog</title>
  <!-- Google Tag Manager -->
  <script>(function(w,d,s,l,i){{w[l]=w[l]||[];w[l].push({{'gtm.start':
  new Date().getTime(),event:'gtm.js'}});var f=d.getElementsByTagName(s)[0],
  j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
  'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
  }})(window,document,'script','dataLayer','GTM-M7N68WTX');</script>
  <!-- End Google Tag Manager -->
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #8b949e;
      --link: #58a6ff;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont,\
 'Segoe UI', Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem 1rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      text-align: center;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
    }}
    header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
    header p {{ color: var(--text-muted); font-size: 1.1rem; }}
    .stats {{
      display: flex;
      justify-content: center;
      gap: 2rem;
      margin-top: 1rem;
    }}
    .stat {{
      text-align: center;
      padding: 0.5rem 1rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .stat-value {{ font-size: 1.5rem; font-weight: bold; }}
    .stat-label {{ color: var(--text-muted); font-size: 0.85rem; }}
    .install-box {{
      text-align: center;
      margin: 1.5rem 0;
      padding: 1rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .install-box code {{
      background: var(--bg);
      padding: 0.4rem 0.8rem;
      border-radius: 4px;
      font-size: 1rem;
      color: var(--link);
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 1.5rem;
      margin-top: 2rem;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      transition: transform 0.15s ease;
    }}
    .card:hover {{ transform: translateY(-2px); }}
    .card-link {{
      display: block;
      color: inherit;
      text-decoration: none;
    }}
    .card-link:hover h2 {{ color: var(--link); }}
    .card-header {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.75rem;
    }}
    .card-header h2 {{ font-size: 1.1rem; flex: 1; }}
    .icon {{ font-size: 1.3rem; }}
    .badge {{
      color: #fff;
      font-size: 0.75rem;
      padding: 0.15rem 0.5rem;
      border-radius: 10px;
      font-weight: 600;
    }}
    .description {{
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-bottom: 0.75rem;
      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }}
    .technique-list {{
      list-style: none;
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }}
    .technique-list li {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.15rem 0.5rem;
      font-size: 0.8rem;
    }}
    .technique-list a {{
      color: var(--link);
      text-decoration: none;
    }}
    .technique-list a:hover {{ text-decoration: underline; }}
    footer {{
      text-align: center;
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.85rem;
    }}
    footer a {{ color: var(--link); text-decoration: none; }}
    footer a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <!-- Google Tag Manager (noscript) -->
  <noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-M7N68WTX"
  height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
  <!-- End Google Tag Manager (noscript) -->
  <div class="container">
    <header>
      <h1>CTF Skills Catalog</h1>
      <p>Agent Skills for solving Capture The Flag challenges</p>
      <div class="stats">
        <div class="stat">
          <div class="stat-value">{total_categories}</div>
          <div class="stat-label">Categories</div>
        </div>
        <div class="stat">
          <div class="stat-value">{total_techniques}</div>
          <div class="stat-label">Technique Files</div>
        </div>
      </div>
      <div class="install-box">
        <code>npx skills add ljagiello/ctf-skills</code>
      </div>
    </header>
    <div class="grid">
      {"".join(cards)}
    </div>
    <footer>
      <a href="{_get_repo_url()}">GitHub Repository</a>
      &middot;
      <a href="https://agentskills.io">Agent Skills</a>
      &middot;
      MIT License
    </footer>
  </div>
</body>
</html>"""


def main() -> None:
    skills = []
    for skill_dir in discover_skills():
        text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        fm = parse_frontmatter(text)
        techniques = count_techniques(skill_dir)
        skills.append(
            {
                "dir_name": skill_dir.name,
                "description": fm.get("description", ""),
                "techniques": techniques,
            }
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    catalog_html = build_html(skills)
    (OUT_DIR / "index.html").write_text(catalog_html, encoding="utf-8")
    print(f"Catalog generated: {OUT_DIR / 'index.html'}")
    total = sum(len(s["techniques"]) for s in skills)
    print(f"  {len(skills)} skills, {total} technique files")


if __name__ == "__main__":
    main()
