# Installing GRT Sentry

The program is at version **0.1.0**, and the same version runs on Linux and on
Windows.

---

## The short way: download one

Every release carries a ready-made file for both systems. Nothing else has to
be installed to use them.

**Linux.** Take the `.AppImage`. It is one file, it needs no installation and
no administrator rights, and it runs from anywhere:

```bash
chmod +x grt-sentry-0.1.0-linux-x86_64.AppImage
./grt-sentry-0.1.0-linux-x86_64.AppImage
```

The `.deb` and `.rpm` beside it install through the package manager instead,
which puts the program in the application menu:

```bash
sudo apt install ./grt-sentry-0.1.0-linux-x86_64.deb     # Debian, Ubuntu
sudo dnf install ./grt-sentry-0.1.0-linux-x86_64.rpm     # Fedora
```

**Windows.** Take `grt-sentry-0.1.0-windows-x86_64-setup.exe`. The plain `.exe`
beside it is the same program with no installer, for a portable copy. Neither
is code-signed, so Windows will warn about an unknown publisher.

Three of the checks need administrator rights on Windows: blocking an address,
closing a connection, and reading failed logons out of the Security event log.
To use those, right-click GRT Sentry and choose **Run as administrator**.
Everything else works without it, and the program says which parts are
unavailable rather than failing quietly.

---

## Building from source

Requires Node 22 and a Rust toolchain.

**Linux** also needs the WebKitGTK development libraries:

```bash
sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev build-essential curl file libssl-dev libayatana-appindicator3-dev librsvg2-dev nftables
```

**Windows** needs the Microsoft C++ build tools, which the Rust installer
offers to fetch, and WebView2, which Windows 10 and 11 already have.

Then, on either:

```bash
npm install
npm run build            # packages for this system
npm run build:binary     # just the executable
```

The result is `src-tauri/target/release/grt-sentry`, or `grt-sentry.exe` on
Windows, and the packages under `src-tauri/target/release/bundle/`.

Build through those scripts rather than `cargo build --release` directly. A
bare cargo build produces a working program whose binary contains the absolute
path of the directory it was compiled in, which `scripts/check-build.sh` will
tell you about.

On Linux, to put a locally built copy in the application menu without root:

```bash
./scripts/install-local.sh
```

---

## The optional parts

Everything below is optional. The program runs without any of it and says which
checks are unavailable.

### A VirusTotal key, for the file scanner

Register at virustotal.com, copy the key from your profile, and paste it into
Settings. It is stored in the configuration file, which is written with mode
0600 on Linux, and is never sent to the interface.

The free tier allows four requests a minute, so a scan spaces them 15 seconds
apart and works through a bounded budget, newest files first. Whatever is left
over is checked by the next scan.

### The firewall, for Block address

**Linux.** Once, with sudo:

```bash
sudo ./scripts/setup-nftables.sh
```

That creates an nftables table with two empty sets and a rule that drops
traffic to whatever is in them. Blocking an address adds one element to a set;
the program never writes rules. To see what is blocked:

```bash
sudo nft list table inet grtsentry
```

**Windows.** Nothing to set up. Each block becomes an outbound rule in Windows
Defender Firewall named `GRT Sentry block <address>`, which is also how to find
them in the firewall interface. The program has to be running as administrator.

### Failed logins

**Linux.** `/var/log/auth.log` is readable by the `adm` group on Debian and
Ubuntu. Without that group the module says so and offers to read it once with
administrator rights. The permanent fix:

```bash
sudo usermod -aG adm $USER
```

Then log out and back in.

**Windows.** Failed logons are event 4625 in the Security event log, which only
an elevated process may read. Start GRT Sentry as administrator to include this
check.

### The geolocation database

It is 65 MB of MaxMind data, licensed separately and not distributed here.
Without it the program works normally and connections have no place attached.

Register for a free key at <https://www.maxmind.com/en/geolite2/signup>,
generate a licence key in the account panel, then:

```bash
./scripts/fetch-geoip.sh <your-license-key>
```

That installs it under the user data directory, which the program prefers over
the copy bundled at build time, so it is also how to update it later. Pass
`src-tauri/resources` as a second argument to bundle it into a package instead.

On Windows, download `GeoLite2-City.mmdb` from the MaxMind account panel and
put it in `%LOCALAPPDATA%\grt-sentry\`.

---

## Removing it

**Linux**, if it was installed with the script:

```bash
./scripts/install-local.sh --remove
```

That also removes the scheduled scan. If it was installed from the `.deb` or
`.rpm`, remove it through the package manager. The AppImage is one file: delete
it.

**Windows.** Through Settings, Apps, or by deleting the portable `.exe`.

What is left behind on purpose, because it is yours:

| | Linux | Windows |
|---|---|---|
| Database and quarantine | `~/.local/share/grt-sentry/` | `%LOCALAPPDATA%\grt-sentry\` |
| Configuration | `~/.config/grt-sentry/` | `%APPDATA%\grt-sentry\` |

Anything still in quarantine is in the first of those. Restore what is wanted
before deleting it.

The firewall table, if one was created:

```bash
sudo nft delete table inet grtsentry
```

On Windows, the rules are removed one by one from Windows Defender Firewall, or
with:

```
netsh advfirewall firewall delete rule name=all dir=out program=any
```

filtered to the rules whose name starts with `GRT Sentry block`.
