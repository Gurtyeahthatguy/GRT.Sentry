# GRT Sentry

A security scanner for the machine it runs on. It opens, checks, shows what it
found, and offers something to do about each thing.

- **Six checks, one answer.** Files, network connections, pending updates,
  startup entries, failed logins, system file integrity.
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
touches the network. This program asks VirusTotal about files.

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

**Files.** Hashes what is in the download folders and asks VirusTotal how many
engines flag each hash. A file whose size and modification time have not
changed since last time is not read again. Ten or more detections is treated as
malicious, one to nine as worth deciding about, and a file nobody has ever seen
as neither.

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

## Linux and Windows

The two builds are the same program. What differs is who answers the questions,
and in two places the answer is narrower on Windows.

| | Linux | Windows |
|---|---|---|
| Files, VirusTotal, quarantine, trusted list | the same | the same |
| Open connections | `/proc/net` | the Win32 socket table, **TCP only** |
| Close one connection | `ss --kill` | `SetTcpEntry`, **IPv4 TCP only** |
| Block an address | an nftables set | a Defender Firewall rule |
| Stop a process | SIGTERM | `taskkill` |
| Failed logins | `/var/log/auth.log` | Security event log, event 4625 |
| Startup entries | desktop files, user units, cron | Run keys, Startup folder, scheduled tasks |
| Pending updates | `apt`, security pocket only | `winget`, every pending upgrade |
| Forced libraries | `/etc/ld.so.preload` | `AppInit_DLLs` |
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
| A file nobody has seen | Send for analysis, Trust this file, Ignore |
| A connection | Close connection, Stop process, Block address, Trust, Ignore |
| Failed logins from an address | Block address, Expected, Ignore |
| A changed system file | This was expected, Ignore |
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

**The Settings tab** holds the API key, the folders to scan, the thresholds and
the scheduled scan. At the bottom it lists where everything lives and whether
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

123 tests. Among them: a file is re-hashed when its size or modification time
change and skipped when they do not; hashing a large file gives the same answer
as hashing those bytes in one piece; VirusTotal requests are exactly the
configured interval apart; a quarantined file crossing a filesystem boundary is
copied, verified against its hash and only then removed; a private address is
never treated as a stranger nor sent to a geolocation lookup; the filter that
closes a connection matches that socket and no other; and a scan where every
module is unavailable still produces a result.

To look at the interface without building anything:

```bash
./scripts/preview-ui.sh
```

## Limits

- A scanner that arrives after the fact takes the machine as it finds it. The
  first run records what starts automatically and what the system files contain
  now. On a machine already suspected of being compromised, investigate from
  outside it.
- VirusTotal knows about files, not behaviour. New malware is a file nobody has
  seen, which this reports as exactly that: an absence of information, not a
  clean bill of health.
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
