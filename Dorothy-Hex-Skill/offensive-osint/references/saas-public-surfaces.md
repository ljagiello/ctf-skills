# Public SaaS Collaboration Surfaces

> Reference content for the `offensive-osint` skill. Originally §24 + §25 + §26 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 24. Postman Public Workspace Universal Search

Postman's public-search endpoint is unauthenticated and indexes every workspace marked public.

**Verified endpoint shape (mid-2025 onward):**

```bash
curl -sk -m 15 \
  "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' \
  -H 'X-Entity-Team-Id: 0' \
  -d '{
    "service":"search",
    "method":"POST",
    "path":"/search-all",
    "body":{
      "queryIndices":["collaboration.workspace","runtime.collection","runtime.request"],
      "queryText":"acme.com",
      "size":100,
      "from":0,
      "clientTraceId":"",
      "queryAllIndices":false,
      "domain":"public"
    }
  }' | jq '.data[]'
```

This proxies through Postman's web app to their internal search service. Pagination via `from` (0, 100, 200, ...).

**If the proxy shape changes** (it has historically): inspect a real search request from the Postman web UI:
1. Open `https://www.postman.com/explore` in a browser.
2. Open DevTools → Network tab.
3. Search for any term.
4. Find the request to `_api/...` — copy as cURL — adapt.

**Per-workspace walk:**

For each matching workspace ID:

```bash
WS_ID="<workspace-id>"
# Workspace metadata (name, description, team, visibility)
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID" | jq .

# List collections + environments + monitors in workspace
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID/collection" | jq '.[].id'
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID/environment" | jq '.[].id'

# Per-collection: full content (requests, headers, scripts, env vars)
COL_ID="<collection-id>"
curl -sk -m 10 "https://www.postman.com/_api/collection/$COL_ID" | jq '.collection.item[]'
```

**Ownership scoring signals:**
- Creator/team name mentions target domain or brand → strong.
- Workspace name/description mentions target → strong.
- Request URLs contain `*.target.com` → strongest signal (workspace is actively used against target's APIs).

**Run secret catalog (§17) over every text blob extracted** from the requests, env vars, pre-request scripts, and test scripts.

---

## 25. Stack Exchange OSINT Sweep

Stack Exchange and its sister sites collect code paste-ins from developers — many include secrets, internal hostnames, and proprietary code excerpts.

**Sites to query (8 with highest signal):**
```
stackoverflow.com
serverfault.com
dba.stackexchange.com
devops.stackexchange.com
security.stackexchange.com
superuser.com
sharepoint.stackexchange.com
salesforce.stackexchange.com
```

**API:**
```
GET https://api.stackexchange.com/2.3/search/advanced
   ?site=<site>
   &q=<target>
   &filter=withbody
   &pagesize=100
```

**Code block extraction regex:**
```regex
<pre><code>([\s\S]*?)</code></pre>
```
(Stack Exchange wraps code in `<pre><code>` HTML.)

**Pipeline:**
1. Search each site for the target name, brand, root domain.
2. Extract code blocks from `body` HTML.
3. Run secret catalog (§17) over each block.
4. Cross-reference post author email (where exposed in profile) against email_osint discoveries — confirms employee posting target's internal code.
5. Extract hostnames from code blocks → upsert as `subdomain` assets.

**Quota:** Stack Exchange API permits 30 requests/day without a key; with a free key, 10,000/day. Throttle with 2-second min interval per call.

---

## 26. Public SaaS Collaboration Surfaces

Many SaaS collaboration tools allow public sharing. Dork them like search engines.

**Platforms with high incident rate:**
```
trello.com
notion.so / notion.site
*.atlassian.net           (Jira / Confluence)
miro.com
asana.com
clickup.com
airtable.com
```

**Dork template:**
```
site:{platform} "{target-keyword}"
```

**Run via search-engine adapter** (DDG default; Bing / Brave / Yandex / SerpAPI optional). The same classification logic from §18.7 applies.

**Common findings:**
- Public Trello board with credentials in card titles or attached config files.
- Public Notion page with internal SOPs, API keys in code blocks, customer data.
- Public Confluence space with onboarding docs containing seed creds.
- Public Miro board with architecture diagrams revealing internal hostnames.

---

