# GRT Sentry

A security scanner for the machine it runs on. It opens, checks, shows what it
found, and offers something to do about each thing.

- **One answer for the whole machine.** Files, connections, processes,
  rootkits, startup entries, logins and accounts, browser extensions,
  privileged files, system folders, packaged programs, the settings that leave
  a door open, and pending updates.
- **Offline first.** Files are judged by rules that ship with the program, and
  archives are opened and judged too. VirusTotal adds its engines when given a
  key; nothing depends on it.
- **On demand.** Nothing runs in the background unless it is switched on.
- **It remembers.** Every problem carries its history: new in this scan, seen
  in the last five, or set aside. What was set aside stays aside until it
  changes, and a notification comes only for something new.
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

**Processes.** Every process this user may inspect, and where its program
lives: deleted from the disk, held only in memory, or in a temporary folder
anyone can write to. A program still running the version an update replaced
is told apart and mentioned once, as a reminder.

**Rootkits.** What a rootkit hides is found by asking the kernel twice. A
process that answers at `/proc/PID` but is missing from the listing, a TCP port
that cannot be bound but holds no visible socket, a kernel module in
`/sys/module` that `/proc/modules` leaves out. Modules built outside the
kernel, such as graphics drivers, are recorded once and only a new one is
reported.

**Startup entries.** Desktop entries, user and system services, user and
system cron, the scripts in `/etc/cron.*`, the modules loaded at boot, and each
line of the files a shell reads when it starts. Recorded the first time each
place is read, and afterwards only what is new is reported. A list of forty
legitimate entries says nothing; "this one was not here yesterday" says a lot,
and it stays on the list until it is marked Expected or set aside.
A new line in `.bashrc` is information unless the rules see something in it.

**Logins and accounts.** Counts authentication failures per address in the
last 24 hours, from `/var/log/auth.log` or from the journal, and offers to
block the ones that are clearly knocking. A second account with user ID 0, a
new account that can log in, a user who starts using sudo, and an SSH login at
an hour when the machine has never seen one are each reported.

The automatic response, off until it is switched on in Settings, gathers every
address past a number of failures into one card with one button that blocks
them all for 24 hours, with one password. A scan run as root blocks them
without asking. Either way each block is in the action log and can be lifted
sooner, and an address that is blocked is not offered again.

**Browser extensions.** Firefox and the Chromium family, including the snap
and flatpak builds. An extension that did not come from the store, loaded
unpacked, placed by another program or forced in by a policy, is reported until
it is accepted. One from the store is mentioned when it is new.

**Privileged files.** Set-user-ID, set-group-ID and file capabilities. One on a
program that can be asked to start a shell, such as `find` or an interpreter,
is root for everyone; one no package installed, or in a temporary folder or
the home, is how a machine is kept open. The list of programs that escalate
was written for this program. Nothing is changed.

**System folders.** In `/usr/bin` and `/usr/sbin` every file should come from a
package: one that does not is reported at once. In the parts of `/etc` that
decide who logs in and what runs as root (`sudoers.d`, `pam.d`, `ld.so.conf.d`,
`systemd/system`, the cron folders and a few more), a change is quiet when it
is the package's own version of the file, as after an update, and reported
otherwise.

**Settings that leave a door open.** SSH that lets root or an empty password
in, sudo rules that give root without a password, a folder on the search path
that anyone can write to.

**System file integrity.** Keeps a hash of a short list of files and says when
one changes. A system update changes some of them legitimately, so every such
issue offers "this was expected", which makes the new contents the reference.
It also reports a library forced into every process that starts, which is how a
rootkit hides.

**Your own rules and indicators.** YARA files in `~/.config/grt-sentry/rules/`
run with every scan, inside archives too. `~/.config/grt-sentry/indicators.txt`
takes hashes, file names, paths and IP addresses, one per line, with a note
after the first space; a match on a file, a running program or a connection is
critical. Both change only when you edit them.

**A saved capture.** GRT Sentry never captures traffic, but it reads a `.pcap`
or `.pcapng` that tcpdump or Wireshark recorded: who talked to whom, on which
port, how much. Every address is compared with your indicators, and a match
joins the Status list like any other problem. Only headers are read.

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
| Block for 24 hours | an nftables set whose elements time out | a firewall rule the first elevated scan after the day removes |
| Stop a process | SIGTERM | `taskkill` |
| Failed logins | `/var/log/auth.log` | Security event log, event 4625 |
| Startup entries | desktop files, user units, cron | Run keys, Startup folder, scheduled tasks |
| Pending updates | `apt`, security pocket only | `winget`, every pending upgrade |
| Forced libraries | `/etc/ld.so.preload` | `AppInit_DLLs` |
| Packaged programs | dpkg or rpm records | **not checked**: Windows keeps no record to compare against |
| Processes | `/proc` | the process list and each program's path |
| Hidden processes, ports, modules | compared against `/proc` and `/sys` | **not checked**: no second listing to compare |
| Privileged files, system folders, SSH, sudo, PATH | checked | **not checked** |
| Browser extensions | Firefox, Chrome, Chromium, Brave, Edge, Vivaldi | the same |
| Scheduled scan | systemd user timer | Task Scheduler |
| Notifications | `notify-send` | a toast, under GRT Sentry's name when installed |
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
found. Otherwise every problem is a card: what it is, where it is, whether it
is new or how many scans have reported it, and a row of buttons. Destructive
buttons ask for confirmation.

| Problem | What is offered |
|---|---|
| A file engines flag | Quarantine, Delete, Trust this file, Set aside |
| A file a rule matches, or an archive with one inside | Quarantine, Delete, Trust this file, Set aside |
| An archive a limit or a password kept from view | Quarantine, Delete, Trust this file, Set aside |
| A file nobody has seen | Send for analysis, Trust this file, Set aside |
| A connection | Close connection, Stop process, Block address, Trust, Set aside |
| Failed logins from an address | Block address, Expected, Set aside |
| Addresses past the automatic response's limit | Block for 24 hours, Set aside |
| A changed system file | This was expected, Set aside |
| A system program that differs from its package | This was expected, Set aside |
| A process running from somewhere odd | Stop process, Set aside |
| A new kernel module, extension, account or privileged file | Expected, Set aside |
| A changed file in a watched system folder | This was expected, Set aside |
| Unreadable sudo rules | Read with administrator rights, Set aside |
| Pending updates | Show the whole list, Set aside |
| A new startup entry | Expected, Set aside |

**Set aside** moves a card to a folded list at the bottom. It no longer counts
towards the verdict, and later scans keep it there for as long as it stays the
same: a file until its contents change, an address, a startup entry or a
setting until it is a different one. *Bring back* undoes it. **Trust** is
stronger: a trusted file or address stops being reported at all.

**Save as evidence** on any card writes a zip with what was found, what GRT
Sentry did about it, the log lines that mention it and the files it is about.
The files go in encrypted with the password `infected`, the usual convention
for passing samples on, so no antivirus deletes the archive on the way and
nobody opens a sample by mistake. Every entry carries the same date and
permissions, so the archive says nothing about the machine beyond what is in
it.

**The Connections tab** is the full list of open sockets, with the process that
owns each one and where the remote address is announced from. *Close* ends one
connection; *Trust* stops that address being reported. The filter box matches
process names, addresses and places. *Read a capture* opens a saved `.pcap` or
`.pcapng` and lists its conversations, biggest first, with any address from
your indicators at the top.

An unwanted connection has three answers, in increasing order of force:

1. **Close connection** ends this conversation. The program stays running and
   can open another one immediately.
2. **Block address** adds it to the firewall. Nothing reaches it until it is
   unblocked.
3. **Stop process** asks the program that opened it to stop.

**The Quarantine tab** holds the files that were moved out of the way, the log
of everything GRT Sentry has done, and the lists of trusted files and trusted
addresses. *Look inside* reads a quarantined file without running it: what the
bytes say it is, and whether its name pretends otherwise, its SHA-256 and MD5,
its entropy, the readable strings with addresses and commands picked out, and
the rules it matches. *Save as evidence* writes the same zip as on a card.
*Put back* restores a file to its original path, contents and permissions.
*Undo* on a log line reverses a block or a quarantine. Nothing here deletes
anything until *Delete for good* is pressed.

**The History tab** lists past scans. Each one opens as a report, plain text to
read, print or send, and *What changed* compares it with the scan before:
what appeared and what went. The latest hundred scans keep everything they
found.

**The Settings tab** holds the API key, the folders to scan and to skip, the
thresholds, the package check and the scheduled scan. At the bottom it lists where everything lives and whether
the optional pieces are present.

**A scheduled scan** runs the same checks without a window and notifies only
when something new needs attention: what it already said yesterday stays
quiet. Turn it on in Settings.

Keyboard: Ctrl+1 to Ctrl+5 change tab.

## The command line

```
grt-sentry                 open the window
grt-sentry --scan          run a scan without a window and print the result
grt-sentry --status        print the result of the last scan
grt-sentry --report        print the last scan in full, to save or send
grt-sentry --compare       print what changed between the last two scans
grt-sentry --connections   list the active network connections
grt-sentry --where         print where the data, configuration and quarantine live
```

`--scan` exits 0 when nothing above information was found and 1 when something
was, so it fits into a script; what was set aside does not count. It is also
what the scheduled scan runs.

## Where things are

| What | Linux | Windows |
|---|---|---|
| Database and quarantine | `~/.local/share/grt-sentry/` | `%LOCALAPPDATA%\grt-sentry\` |
| Configuration, including the API key | `~/.config/grt-sentry/config.toml` | `%APPDATA%\grt-sentry\config.toml` |
| Your rules and indicators | `~/.config/grt-sentry/rules/`, `indicators.txt` | `%APPDATA%\grt-sentry\rules\`, `indicators.txt` |

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

253 tests. Among them: with no key and no network, EICAR is found on its own
and inside a zip; a zip, a gzip and a tar.gz bomb are each stopped and named,
and an honest log file that compresses well is not; a replaced program in a fake
dpkg tree is found and an untouched one is not; every rule has a sample it must
match and the benign lookalikes it must not, such as the rustup installer line
and a port check through `/dev/tcp`; a file is re-hashed when its size or
modification time change and skipped when they do not; VirusTotal requests are
exactly the configured interval apart; a quarantined file crossing a filesystem
boundary is copied, verified against its hash and only then removed; and a scan
where every module is unavailable still produces a result; a module that hides
from /proc/modules, a second root account, a sudo rule without a password, a
command linked into /tmp, a Firefox extension sideloaded by another program and
a `.bashrc` line that opens a reverse shell are each found, and an update that
ships a new version of a PAM file is not reported; EICAR set aside in one scan
is still aside in the next and not called new, while the same file with new
contents is; a notification comes only for something new; an evidence archive
opens without a password except for its samples, and holds no real date; a
pcap and a pcapng of the same packets give the same conversations; and
failed logins from a trusted address or from the local network are never
offered for blocking. No malware sample is
stored anywhere: EICAR is built at run time, and the rest are a line or two of
text.

```bash
./scripts/check-false-positives.sh
```

Runs the rules and the archive reader over every file under `/usr`, `/etc` and
`/opt` and counts what they would report, then every system check twice on the
machine it runs on. The budget for a clean machine is zero in both, and the
first half is checked on every push. The second scan may not report anything
new either, pending updates and failed logins included: those describe the
machine's real life, and the history already knows them. On a desktop Debian install:
190,000 files, 9 GB and 177,000 archive members in 83 seconds, no alarms, and
171 MB of memory at the peak.

```bash
./scripts/test-planted.py <debian-live.iso> <grt-sentry.deb>
```

Boots a Debian live image in QEMU with no network, installs the package, and
scans the untouched system as the live user and as root: neither may raise an
alarm. Then it plants 25 samples, among them a replaced `whoami`, a
set-user-ID shell in `/tmp`, a cron job and a systemd unit, a second root
account, a sudo rule without a password, a process run from a deleted file,
and a library in `/etc/ld.so.preload` that hides a process from every listing
of `/proc`. All 25 must be named. A last root scan with the automatic response
on must call none of them new, and must block for a day an address that keeps
failing to log in. Last run: 25 of 25, no alarm on the clean image, none of the
22 alarms called new the second time, the address blocked for a day, the
profile in enforce and no AppArmor denial.

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
- An ordinary user sees only part of the machine: processes of other users,
  `/etc/sudoers` and `/etc/sudoers.d` are root's, and TCP ports below 1024
  cannot be probed. `sudo grt-sentry --scan` sees all of it.
- A rootkit in the kernel can lie to both listings at once. What is compared
  here catches the ones that lie to one, which is most of them; for the rest,
  boot from a live USB and look from outside.
- The geolocation says where the network announcing an address is registered.
  That is a data centre or a provider, not a person and not a street.
- Blocking an address stops this machine reaching it. It is an outbound rule,
  not an inbound firewall; for a stranger knocking on SSH that is enough, since
  no answer gets back.
- The blocks that last 24 hours need `scripts/setup-nftables.sh` run again on
  a table made before 0.4, which adds the two sets that time out. On Windows a
  firewall rule cannot expire, so the first scan run as administrator after the
  day removes it.
- The password on an evidence archive is a convention, not protection: anyone
  who knows it can open the files, and the archive's encryption is the old zip
  kind every tool can read.
- On Windows the connections list is TCP only, and only IPv4 TCP connections
  can be closed. Windows exposes no peer for a UDP association and no call that
  ends an IPv6 connection.

## Licence

MIT. See [LICENSE](LICENSE).

The GeoLite2 data, if installed, is MaxMind's and carries its own terms.
