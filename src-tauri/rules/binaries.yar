// SPDX-License-Identifier: MIT
// Compiled programs and the notes ransomware leaves behind.

rule upx_packed
{
    meta:
        severity = "info"
        title = "Program compressed with UPX"
        detail = "UPX shrinks a program and unpacks it in memory when it runs. Some honest programs use it; much malware does too, because it also hides the contents from a scanner. On its own it proves nothing."

    strings:
        $mark = "UPX!"
        $section0 = "UPX0"
        $section1 = "UPX1"

    condition:
        (uint32(0) == 0x464C457F and $mark in (0..4096)) or
        (uint16(0) == 0x5A4D and $section0 in (0..1024) and $section1 in (0..1024))
}

rule ransom_note
{
    meta:
        severity = "critical"
        title = "Ransom note"
        detail = "Text saying that files were encrypted and asking for payment. Its presence usually means ransomware has already run on this machine, or on a share this machine can reach. Disconnect it from the network before anything else."

    strings:
        $encrypted = /your (important |personal )?(files|documents|data)[^\n.]{0,30}(have been|are|were) encrypted/ nocase ascii wide
        $wallet = /(bitcoin|btc|monero|xmr)\s+(wallet|address)/ nocase ascii wide
        $onion = /[a-z2-7]{56}\.onion/ ascii wide
        $tor = "Tor Browser" nocase ascii wide
        $decrypt = /decrypt(ion|or)?\s+(tool|key|software|program|your files)/ nocase ascii wide
        $deadline = /(within|in|after)\s+[0-9]{1,3}\s+(hours|days)/ nocase ascii wide

    condition:
        filesize < 64KB and $encrypted and 2 of ($wallet, $onion, $tor, $decrypt, $deadline)
}
