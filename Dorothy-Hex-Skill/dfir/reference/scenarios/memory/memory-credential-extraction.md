# Credential Extraction from Memory

## When this applies

Windows memory dump (full system or LSASS-only) and you need to recover plaintext passwords, NTLM hashes, Kerberos tickets, or DPAPI master keys. Used to scope an attacker's foothold or reconstruct what credentials they captured.

## Technique

LSASS holds active session secrets. Mimikatz's `sekurlsa::*` family parses `wdigest`, `tspkg`, `kerberos`, `msv` (NT/LM/NTLMv2), and `livessp` packages directly from LSASS memory. From a forensic dump, the same structures are accessible offline via `pypykatz`, `mimikatz` `sekurlsa::minidump`, or Volatility's `windows.hashdump` / `windows.lsadump` / `windows.cachedump`.

## Steps

1. If only LSASS is dumped (e.g. `lsass.dmp`):
   ```bash
   pip install pypykatz
   pypykatz lsa minidump lsass.dmp
   ```
   Outputs: NT/LM hashes, Kerberos tickets, plaintext passwords (Wdigest if pre-2017 or KB enabled).
2. Full memory dump path with mimikatz:
   ```
   # On a Windows analysis VM matching the target's bitness
   mimikatz # sekurlsa::minidump lsass.dmp
   mimikatz # sekurlsa::logonpasswords full
   ```
3. Volatility 3:
   ```bash
   vol -f memory.raw windows.hashdump            # SAM NT/LM
   vol -f memory.raw windows.lsadump             # LSA secrets (DefaultPassword, machine acct, services)
   vol -f memory.raw windows.cachedump           # MSCASH / DCC2 (offline domain logons)
   ```
4. Hash crack:
   ```bash
   hashcat -m 1000 nt.txt rockyou.txt            # NT
   hashcat -m 2100 dcc2.txt rockyou.txt          # MSCASH/DCC2
   ```
5. Kerberos ticket extraction (vol3 / mimikatz):
   ```bash
   pypykatz lsa minidump lsass.dmp -k kerberos_out/
   # Produces .kirbi files; convert with kekeo or impacket ticketConverter.py
   ticketConverter.py ticket.kirbi ticket.ccache
   export KRB5CCNAME=$PWD/ticket.ccache
   ```
6. DPAPI master keys for offline Chrome/IE/Edge credential decryption:
   ```bash
   pypykatz lsa minidump lsass.dmp -k dpapi_out/
   # Or: mimikatz sekurlsa::dpapi
   # Decrypt blobs with: dpapi.py -masterkey <hex>
   ```

## Verifying success

- Hash count matches expected user count from `windows.hashdump`.
- Plaintext password for a known account validates against any captured authentication artifact.
- Extracted Kerberos TGT successfully runs `klist` / `getTGS.py` against the domain (only with authorization).

## Common pitfalls

- LSASS protected with `RunAsPPL` (LSA Protection) — older mimikatz reads zeros for password fields. Use `sekurlsa::minidump` from a dump captured *before* protection or use `mimidrv.sys`.
- Windows 11 / Server 2022 changed Wdigest defaults — plaintext rarely present unless explicitly re-enabled by attacker. Focus on NT hashes and tickets.
- Bitness mismatch (32-bit mimikatz on 64-bit dump) silently fails. Match the target architecture.
- DCC2 / MSCASH hashes are slow to crack (ASIC-resistant). Only attempt with strong wordlists for high-value users.
- Some EDRs zero credential pages on detection. If `pypykatz` returns empty packages but the dump is correct size, suspect a redacted dump.

## Tools

- `pypykatz` — pure-Python, cross-platform LSASS parser
- `mimikatz` `sekurlsa::minidump`, `sekurlsa::logonpasswords`, `sekurlsa::tickets`, `sekurlsa::dpapi`
- `volatility3` — `windows.hashdump`, `windows.lsadump`, `windows.cachedump`
- `impacket-secretsdump` — works on offline SAM/SECURITY/SYSTEM hives
- `hashcat` — NT (1000), DCC2 (2100), Kerberos (13100/19900)
