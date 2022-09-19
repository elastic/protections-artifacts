rule Windows_Trojan_Cryptbot_489a6562 {
    meta:
        author = "Elastic Security"
        id = "489a6562-870c-4105-9bb7-52ab09e5b09c"
        fingerprint = "f4578d79f8923706784e9d55a70ec74051273a945d2b277daa6229724defec3f"
        creation_date = "2021-08-18"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Cryptbot"
        reference_sample = "423563995910af04cb2c4136bf50607fc26977dfa043a84433e8bd64b3315110"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/c rd /s /q %Temp%\\" wide fullword
        $a2 = "\\_Files\\_AllPasswords_list.txt" wide fullword
        $a3 = "\\files_\\cryptocurrency\\log.txt" wide fullword
        $a4 = "%wS\\%wS\\%wS.tmp" wide fullword
        $a5 = "%AppData%\\waves-exchange" wide fullword
    condition:
        all of them
}

