rule Windows_Trojan_Guloader_8f10fa66 {
    meta:
        author = "Elastic Security"
        id = "8f10fa66-a24b-4cc2-b9e0-11be14aba9af"
        fingerprint = "5841d70a38d4620c446427c80ca12b5e918f23e90c5288854943b0240958bcfb"
        creation_date = "2021-08-17"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Guloader"
        reference_sample = "a3e2d5013b80cd2346e37460753eca4a4fec3a7941586cc26e049a463277562e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "msvbvm60.dll" wide fullword
        $a2 = "C:\\Program Files\\qga\\qga.exe" ascii fullword
        $a3 = "C:\\Program Files\\Qemu-ga\\qemu-ga.exe" ascii fullword
        $a4 = "USERPROFILE=" wide fullword
        $a5 = "Startup key" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Guloader_c4d9dd33 {
    meta:
        author = "Elastic Security"
        id = "c4d9dd33-b7e7-4ff4-a2f3-62316d064f5a"
        fingerprint = "53a2d6f895cdd1a6384a55756711d9d758b3b20dd0b87d62a89111fd1a20d1d6"
        creation_date = "2021-08-17"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Guloader"
        reference_sample = "a3e2d5013b80cd2346e37460753eca4a4fec3a7941586cc26e049a463277562e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "This program cannot be run under virtual environment or debugging software !" ascii fullword
    condition:
        all of them
}

