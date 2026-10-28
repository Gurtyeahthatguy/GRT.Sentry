# GRT Sentry

A security scanner for the machine it runs on. It opens, checks, shows what it
found, and offers something to do about each thing.

- **Seven checks, one answer.** Files, network connections, pending updates,
  startup entries, failed logins, system file integrity, packaged programs.
- **Offline first.** Files are judged by rules that ship with the program, and
  archives are opened and judged too. VirusTotal adds its engines when given a
  key; nothing depends on it.
- **On demand.** Nothing runs in the background unless it is switched on.
- **Reversible.** Quarantine before deletion, an undo log, and a firewall it
  drives rather than replaces.
- **Small.** Built for machines with under 4 GB of memory: no framework, no
  resident process, and a hash cache so the second scan is not the first one
  again.

Ready-made programs for Linux and Windows are attached to each release.
Building and installing: [INSTALL.md](INSTALL.md).

It belongs to the GRT family but is separate from [GRT
Office](https://github.com/Gurtyeahthatguy/GRT.Office), which promises it never
touches the network. This program asks VirusTotal about files, when it has a
key.

## What leaves the machine

| What | Where | When |
|---|---|---|
| The SHA-256 of a file, 64 characters that cannot be turned back into it | VirusTotal | During a scan, if an API key is set |
| The contents of a file | VirusTotal | Only by pressing **Send for analysis** on an issue and confirming |
| Nothing else | | |

Locating an IP address uses a MaxMind database file on disk, not a lookup
service, because a lookup service would learn every address the machine talks
to. There is no telemetry, no update check and no analytics. See
[Checking the claims](#checking-the-claims) for how to confirm that.

## What it checks

**Files.** Reads what is in the download folders and runs it through GRT
Sentry's own rules: reverse shells, scripts that download and run something,
persistence in cron, launchers and services, PHP web shells, encoded
PowerShell, Windows script droppers, cryptocurrency miners, ransom notes, and
the EICAR test file. The rules are [YARA](src-tauri/rules), run by
[yara-x](https://github.com/VirusTotal/yara-x), and need no network and no key.

Archives are opened in memory, never on disk: `.zip` (and `.jar`, `.apk` and
the other formats that are zips underneath), `.tar`, `.gz`, `.tar.gz` and `.7z`.
Every file inside is hashed and run through the rules, and an archive inside an
archive is opened in turn, three levels down. A file that unpacks to more than
two hundred times its compressed size is a decompression bomb and is reported
as one, without being unpacked. Whatever a limit or a password kept from view
is reported too, never skipped in silence.

With a VirusTotal key, each file's hash is also looked up: ten or more engines
is treated as malicious, one to nine as worth deciding about, and a file nobody
has ever seen as neither. A file whose size and modification time have not
changed since last time is not read again.

Folders full of generated files are skipped: `.git`, `node_modules`, `.cache`,
`__pycache__`, `.venv`, and any folder holding a `CACHEDIR.TAG`, which Cargo,
pip and most build tools leave in their output. The list is in Settings.

**Connections.** Reads the open sockets, matches each to the process that owns
it, and marks the addresses this machine has never talked to before. Each
remote address gets a place from the offline GeoLite2 database. A new address
is never an alarm on its own: visiting a site for the first time is what a
browser is for.

**Pending updates.** Lists what the system's package tool has a newer version
for. It installs nothing: it shows the list and the command.

**Startup entries.** Records what starts automatically the first time it runs,
and afterwards reports only what is new. A list of forty legitimate entries
says nothing; "this one was not here yesterday" says a lot.

**Failed logins.** Counts authentication failures per address in the last
24 hours and offers to block the ones that are clearly knocking.

**System file integrity.** Keeps a hash of a short list of files and says when
one changes. A system update changes some of them legitimately, so every such
issue offers "this was expected", which makes the new contents the reference.
It also reports a library forced into every process that starts, which is how a
rootkit hides.

**Packaged programs.** dpkg keeps an MD5 of every file it installs and rpm a
SHA-256. Each program in `bin` and `sbin`, and each PAM module, which decides
who may log in, is compared with that record. A replaced system program is found
with no network and no signatures. Configuration files are left out, since
editing them is what they are for. Only files whose size or change time moved
are read again, so after the first scan the check costs a few milliseconds.

## Linux and Windows

The two builds are the same program. What differs is who answers the questions,
and in two places the answer is narrower on Windows.

| | Linux | Windows |
|---|---|---|
| Files, rules, archives, VirusTotal, quarantine, trusted list | the same | the same |
| Open connections | `/proc/net` | the Win32 socket table, **TCP only** |
| Close one connection | `ss --kill` | `SetTcpEntry`, **IPv4 TCP only** |
| Block an address | an nftables set | a Defender Firewall rule |
| Stop a process | SIGTERM | `taskkill` |
| Failed logins | `/var/log/auth.log` | Security event log, event 4625 |
| Startup entries | desktop files, user units, cron | Run keys, Startup folder, scheduled tasks |
| Pending updates | `apt`, security pocket only | `winget`, every pending upgrade |
| Forced libraries | `/etc/ld.so.preload` | `AppInit_DLLs` |
| Packaged programs | dpkg or rpm records | **not checked**: Windows keeps no record to compare against |
| Scheduled scan | systemd user timer | Task Scheduler |
| Administrator rights | `pkexec`, asked for per action | the whole program runs elevated, or not |

Windows has no per-command authentication dialog, so blocking an address,
closing a connection and reading the security log need GRT Sentry to have been
started with **Run as administrator**. It says so rather than failing quietly,
and everything else works without it.

**The Windows build has never been run by a person.** It compiles, the workflow
produces it, and the logic it shares with Linux is covered by the tests. The
parts that call Windows itself have not been watched doing their job. Treat
this release as one to try rather than one to rely on, and say so in an issue
if something does not behave.

## Using it

**The first scan** runs when the window opens. It hashes what is in the scan
folders, reads the open connections, checks for updates, and records what
starts automatically and what the watched system files contain. That first run
reports almost nothing: it is establishing what normal looks like. From the
second scan onwards it reports what changed.

**The Status tab** is the answer. Green means nothing above information was
found. Otherwise every problem is a card: what it is, where it is, and a row of
buttons. Destructive buttons ask for confirmation.

| Problem | What is offered |
|---|---|
| A file engines flag | Quarantine, Delete, Trust this file, Ignore |
| A file a rule matches, or an archive with one inside | Quarantine, Delete, Trust this file, Ignore |
| An archive a limit or a password kept from view | Quarantine, Delete, Trust this file, Ignore |
| A file nobody has seen | Send for analysis, Trust this file, Ignore |
| A connection | Close connection, Stop process, Block address, Trust, Ignore |
| Failed logins from an address | Block address, Expected, Ignore |
| A changed system file | This was expected, Ignore |
| A system program that differs from its package | This was expected, Ignore |
| Pending updates | Show the whole list, Ignore |
| A new startup entry | Expected, Ignore |

**Ignore** drops a card from this scan and records nothing. **Trust** is the
permanent version: a trusted file stops being reported until its contents
change, and a trusted address stops being reported at all.

**The Connections tab** is the full list of open sockets, with the process that
owns each one and where the remote address is announced from. *Close* ends one
connection; *Trust* stops that address being reported. The filter box matches
process names, addresses and places.

An unwanted connection has three answers, in increasing order of force:

1. **Close connection** ends this conversation. The program stays running and
   can open another one immediately.
2. **Block address** adds it to the firewall. Nothing reaches it until it is
   unblocked.
3. **Stop process** asks the program that opened it to stop.

**The Quarantine tab** holds the files that were moved out of the way, the log
of everything GRT Sentry has done, and the lists of trusted files and trusted
addresses. *Put back* restores a file to its original path, contents and
permissions. *Undo* on a log line reverses a block or a quarantine. Nothing
here deletes anything until *Delete for good* is pressed.

**The Settings tab** holds the API key, the folders to scan and to skip, the
thresholds, the package check and the scheduled scan. At the bottom it lists where everything lives and whether
the optional pieces are present.

**A scheduled scan** runs the same checks without a window and notifies only
when something needs attention. Turn it on in Settings.

Keyboard: Ctrl+1 to Ctrl+4 change tab.

## The command line

```
grt-sentry                 open the window
grt-sentry --scan          run a scan without a window and print the result
grt-sentry --status        print the result of the last scan
grt-sentry --connections   list the active network connections
grt-sentry --where         print where the data, configuration and quarantine live
```

`--scan` exits 0 when nothing above information was found and 1 when something
was, so it fits into a script. It is also what the scheduled scan runs.

## Where things are

| What | Linux | Windows |
|---|---|---|
| Database and quarantine | `~/.local/share/grt-sentry/` | `%LOCALAPPDATA%\grt-sentry\` |
| Configuration, including the API key | `~/.config/grt-sentry/config.toml` | `%APPDATA%\grt-sentry\config.toml` |

The configuration file is written with mode 0600 on Linux, and on Windows it
inherits the profile's own permissions. Quarantined files are renamed to a
random identifier with no extension and stripped of what permissions the system
allows. Restoring one puts back its original path, contents and permissions; if
something else has taken that name, it is restored beside it rather than over
it.

## Checking the claims

```bash
./scripts/check-build.sh src-tauri/target/release/grt-sentry
```

Reads the release binary and reports absolute build paths, contactable
addresses, telemetry libraries, debug symbols and anything shaped like an
embedded credential. The addresses it tolerates are in
[scripts/allowed-strings.txt](scripts/allowed-strings.txt), each with a written
reason.

```bash
./scripts/check-network.sh src-tauri/target/release/grt-sentry
```

Runs the program under `strace` and lists every address it opened a socket to.
Use it normally, close it, read the list. The expected answer is VirusTotal
during a scan and nothing else.

```bash
cd src-tauri && cargo test
```

176 tests. Among them: with no key and no network, EICAR is found on its own
and inside a zip; a zip, a gzip and a tar.gz bomb are each stopped and named,
and an honest log file that compresses well is not; a replaced program in a fake
dpkg tree is found and an untouched one is not; every rule has a sample it must
match and the benign lookalikes it must not, such as the rustup installer line
and a port check through `/dev/tcp`; a file is re-hashed when its size or
modification time change and skipped when they do not; VirusTotal requests are
exactly the configured interval apart; a quarantined file crossing a filesystem
boundary is copied, verified against its hash and only then removed; and a scan
where every module is unavailable still produces a result. No malware sample is
stored anywhere: EICAR is built at run time, and the rest are a line or two of
text.

```bash
./scripts/check-false-positives.sh
```

Runs the rules and the archive reader over every file under `/usr`, `/etc` and
`/opt` and counts what they would report. The budget for a clean machine is
zero, and it is checked on every push. On a desktop Debian install:
190,000 files, 9 GB and 177,000 archive members in 83 seconds, no alarms, and
171 MB of memory at the peak.

```bash
./scripts/check-weight.sh
```

Holds the binary and every package to [scripts/weight-budget.txt](scripts/weight-budget.txt).
The rules engine is most of the weight: yara-x compiles rules to WebAssembly and
brings wasmtime to run them.

To look at the interface without building anything:

```bash
./scripts/preview-ui.sh
```

## Limits

- A scanner that arrives after the fact takes the machine as it finds it. The
  first run records what starts automatically and what the system files contain
  now. On a machine already suspected of being compromised, investigate from
  outside it.
- The rules are a few dozen, written for this program to catch the obvious
  shapes. They are not a signature database and do not name malware families.
  Something new and careful will match none of them.
- VirusTotal knows about files, not behaviour. New malware is a file nobody has
  seen, which this reports as exactly that: an absence of information, not a
  clean bill of health.
- The package check covers programs and PAM modules, not libraries. A replaced
  `libc` is outside it.
- The geolocation says where the network announcing an address is registered.
  That is a data centre or a provider, not a person and not a street.
- Blocking an address stops this machine reaching it. It is an outbound rule,
  not an inbound firewall.
- On Windows the connections list is TCP only, and only IPv4 TCP connections
  can be closed. Windows exposes no peer for a UDP association and no call that
  ends an IPv6 connection.

## Licence

MIT. See [LICENSE](LICENSE).

The GeoLite2 data, if installed, is MaxMind's and carries its own terms.
