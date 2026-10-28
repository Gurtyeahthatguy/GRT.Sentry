// SPDX-License-Identifier: MIT
// Scripts for other interpreters: PHP web shells, JavaScript, PowerShell and Windows script hosts.

rule php_web_shell
{
    meta:
        severity = "critical"
        title = "PHP web shell"
        detail = "Runs whatever arrives in a web request as code or as a command. Placed on a server, it lets anyone who knows the address control that server."

    strings:
        $run = /(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(base64_decode\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/

    condition:
        $run
}

rule php_obfuscated_eval
{
    meta:
        severity = "warning"
        title = "PHP that runs hidden code"
        detail = "Decompresses or decodes a block of text and runs it as PHP, so that what runs cannot be read in the file. It is how web shells are usually packed."

    strings:
        $eval = /eval\s*\(\s*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|strrev)\s*\(/

    condition:
        $eval
}

rule javascript_eval_decoded
{
    meta:
        severity = "warning"
        title = "JavaScript that runs hidden code"
        detail = "Decodes a block of text and runs it, so that what runs cannot be read in the file. A script that arrived by mail or download and does this is almost always a dropper."

    strings:
        $eval = /eval\s*\(\s*(atob|unescape|String\.fromCharCode)\s*\(/

    condition:
        $eval
}

rule powershell_encoded_command
{
    meta:
        severity = "warning"
        title = "PowerShell with an encoded command"
        detail = "Starts PowerShell with its command given as base64, so that what runs cannot be read in the file. Administrators rarely need it; droppers almost always use it."

    strings:
        $encoded = /powershell(\.exe)?[^\n]{0,80}\s[-\/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedcommand)?\s+[A-Za-z0-9+\/=]{60,}/ nocase ascii wide

    condition:
        $encoded
}

rule powershell_download_and_run
{
    meta:
        severity = "warning"
        title = "PowerShell that downloads code and runs it"
        detail = "Fetches a script from the network and runs it in memory without saving it, which leaves nothing on disk to inspect afterwards."

    strings:
        $iex = /(iex|invoke-expression)\s*\(?\s*\(?\s*new-object\s+(system\.)?net\.webclient\s*\)?\s*\.download(string|data)/ nocase ascii wide
        $irm = /(iwr|irm|invoke-webrequest|invoke-restmethod)\s[^\n|]{0,200}\|\s*(iex|invoke-expression)\b/ nocase ascii wide

    condition:
        any of them
}

rule windows_script_dropper
{
    meta:
        severity = "warning"
        title = "Windows script that downloads and runs a program"
        detail = "A VBScript or JScript file that downloads something, saves it and starts it. Arriving as an attachment or a download, that is the shape of most first-stage malware on Windows."

    strings:
        $shell = "WScript.Shell" nocase ascii wide
        $http1 = "MSXML2.XMLHTTP" nocase ascii wide
        $http2 = "WinHttp.WinHttpRequest" nocase ascii wide
        $stream = "ADODB.Stream" nocase ascii wide
        $run = /\.(Run|Exec)\s*\(/ nocase ascii wide

    condition:
        $shell and $run and ($http1 or $http2) and $stream
}

rule certutil_download
{
    meta:
        severity = "warning"
        title = "Uses certutil to download a file"
        detail = "certutil is a Windows tool for certificates. Its download option is a known way to fetch a program while looking like a system tool doing its job."

    strings:
        $fetch = /certutil(\.exe)?\s[^\n]{0,40}-urlcache\s[^\n]{0,40}https?:\/\// nocase ascii wide

    condition:
        $fetch
}

rule registry_run_key_from_temp
{
    meta:
        severity = "warning"
        title = "Registry file that starts something at every login"
        detail = "Adds a Run or RunOnce entry pointing into a temporary or per-user folder, or at a script host. Merging it makes that program start on its own at every login."

    strings:
        $header = "Windows Registry Editor" ascii wide
        $run = /\\CurrentVersion\\Run(Once)?\]/ nocase ascii wide
        $target = /(\\AppData\\|\\Temp\\|%TEMP%|%APPDATA%|powershell|mshta|wscript|cscript)/ nocase ascii wide

    condition:
        $header and $run and $target
}
