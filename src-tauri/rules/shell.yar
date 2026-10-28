// SPDX-License-Identifier: MIT
// Shell scripts and the files Linux runs on its own: reverse shells, droppers, persistence.

rule reverse_shell_dev_tcp
{
    meta:
        severity = "critical"
        title = "Reverse shell"
        detail = "Starts an interactive shell and connects it to a remote address, which hands control of this account to whoever is listening there."

    strings:
        $interactive = /\b(ba|z|da)?sh\s+-i\s*[0-9>&<\s]*\/dev\/(tcp|udp)\/[^\/\s]+\/[0-9]{1,5}/

    condition:
        $interactive
}

rule reverse_shell_netcat
{
    meta:
        severity = "critical"
        title = "Reverse shell"
        detail = "Uses netcat to connect a shell to a remote address, which hands control of this account to whoever is listening there."

    strings:
        $exec = /\bn(c|cat|etcat)(\.[a-z]+)?\s[^\n|;]{0,80}-[ce]\s*["']?\/bin\/(ba|z|da)?sh\b/
        $fifo = /mkfifo\s[^\n]{0,120}(ba)?sh\s+-i[^\n]{0,120}\|\s*n(c|cat|etcat)\s/

    condition:
        any of them
}

rule reverse_shell_python
{
    meta:
        severity = "critical"
        title = "Reverse shell"
        detail = "A Python program that connects to a remote address and wires a shell's input and output to that connection."

    strings:
        $socket = "socket.socket("
        $connect = /\.connect\(\s*\(/
        $dup = /dup2\(\s*\w+\.fileno\(\)\s*,\s*0\s*\)/
        $pty = /pty\.spawn\(\s*["']\/bin\/(ba)?sh/
        $call = /subprocess\.call\(\s*\[\s*["']\/bin\/(ba)?sh["']\s*,\s*["']-i["']/

    condition:
        $socket and $connect and $dup and ($pty or $call)
}

rule reverse_shell_perl
{
    meta:
        severity = "critical"
        title = "Reverse shell"
        detail = "A Perl program that connects to a remote address and runs a shell over that connection."

    strings:
        $socket = "use Socket"
        $stdin = /open\s*\(\s*STDIN\s*,\s*["']>&/
        $exec = /exec\s*\(?\s*["']\/bin\/(ba)?sh/

    condition:
        all of them
}

rule dropper_to_hidden_temp
{
    meta:
        severity = "warning"
        title = "Downloads a program into a hidden temporary file"
        detail = "Fetches something from the network into a hidden name under /tmp or into /dev/shm, then makes it executable. Installers rarely hide what they download; malware usually does."

    strings:
        $hidden = /(curl|wget)\s[^\n]{0,300}(-o|-O|--output|>)\s*["']?\/(tmp|var\/tmp|dev\/shm)\/\.[^\s"';|&\/]+/
        $shm = /(curl|wget)\s[^\n]{0,300}(-o|-O|--output|>)\s*["']?\/dev\/shm\//
        $chmod = /chmod\s+(\+x|a\+x|u\+x|[0-7]{3,4})\s+["']?\/(tmp|var\/tmp|dev\/shm)\//

    condition:
        ($hidden or $shm) and $chmod
}

rule pipe_to_shell_from_bare_address
{
    meta:
        severity = "warning"
        title = "Runs commands downloaded from a bare IP address"
        detail = "Downloads a script from an address with no name and runs it straight away. Real projects publish installers under a domain; a bare address is how a compromised machine is told what to do next."

    strings:
        $pipe = /(curl|wget)\s[^\n|]{0,200}https?:\/\/[0-9]{1,3}(\.[0-9]{1,3}){3}[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/

    condition:
        $pipe
}

rule decode_and_run
{
    meta:
        severity = "warning"
        title = "Decodes hidden text and runs it as commands"
        detail = "Turns a block of base64 back into text and feeds it to a shell, so that what actually runs cannot be read in the file. Legitimate scripts have no reason to hide their commands."

    strings:
        $pipe = /base64\s+(-d|--decode|-D)[^\n|]{0,40}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
        $eval = /eval\s+["']?\$\(\s*(echo|printf)\s[^\n)]{0,40}[A-Za-z0-9+\/=]{40,}[^\n)]{0,40}\|\s*base64\s+(-d|--decode)/

    condition:
        any of them
}

rule cron_fetch_and_run
{
    meta:
        severity = "warning"
        title = "Schedules a download that runs on its own"
        detail = "A cron line that downloads a script and runs it, every few minutes or at every boot. It is the usual way malware makes sure it comes back after being removed."

    strings:
        $line = /(@reboot|@hourly|(\*|[0-9\/,*-]+)(\s+(\*|[0-9\/,*-]+)){4})\s[^\n]{0,200}(curl|wget)\s[^\n]{0,300}\|\s*(ba|z|da)?sh\b/

    condition:
        $line
}

rule desktop_entry_runs_download
{
    meta:
        severity = "warning"
        title = "A launcher that downloads or decodes before running"
        detail = "A .desktop file whose command fetches something from the network, decodes hidden text or opens a raw connection. Launchers start programs; they do not need to do any of that."

    strings:
        $header = "[Desktop Entry]"
        $exec = /\nExec\s*=[^\n]{0,400}(curl\s|wget\s|base64\s+(-d|--decode)|\/dev\/tcp\/|python[0-9.]*\s+-c\s)/

    condition:
        $header and $exec
}

rule service_runs_from_temp
{
    meta:
        severity = "warning"
        title = "A service that runs a program from a temporary folder"
        detail = "A systemd unit that starts something from /tmp, /var/tmp or /dev/shm. Those folders are writable by everyone and emptied on reboot; nothing installed properly runs from them."

    strings:
        $service = "[Service]"
        $exec = /\nExec(Start|StartPre|StartPost)\s*=\s*[-@+!:]*\/(tmp|var\/tmp|dev\/shm)\//

    condition:
        $service and $exec
}

rule writes_ld_preload
{
    meta:
        severity = "critical"
        title = "Writes the system-wide preload file"
        detail = "Adds a library to /etc/ld.so.preload, which loads it into every program on the machine. It is the mechanism most Linux rootkits use to hide themselves."

    strings:
        $redirect = />\s*\/etc\/ld\.so\.preload/
        $tee = /tee\s+(-a\s+)?\/etc\/ld\.so\.preload/

    condition:
        any of them
}

rule covers_its_tracks
{
    meta:
        severity = "warning"
        title = "Erases the record of what it did"
        detail = "Turns off shell history or empties the login records. One of these alone happens; two together is a script making sure nobody can see afterwards what it did."

    strings:
        $unset = "unset HISTFILE"
        $null = /HISTFILE=\/dev\/null/
        $clear = /history\s+-c\b/
        $logs = /(>|truncate\s[^\n]{0,20}|shred\s[^\n]{0,20})\s*\/var\/log\/(wtmp|btmp|lastlog|auth\.log|secure)/

    condition:
        2 of them
}

rule cryptocurrency_miner
{
    meta:
        severity = "warning"
        title = "Cryptocurrency miner"
        detail = "Mines cryptocurrency for whoever set the pool address. Installed on purpose it is a choice; arrived by itself it is the most common thing attackers run on a machine they have taken."

    strings:
        $pool = /stratum\+(tcp|ssl|tls):\/\//
        $xmrig = "xmrig" nocase
        $donate = "--donate-level"
        $randomx = "randomx" nocase
        $cpuminer = "cpuminer" nocase

    condition:
        $pool and any of ($xmrig, $donate, $randomx, $cpuminer)
}
