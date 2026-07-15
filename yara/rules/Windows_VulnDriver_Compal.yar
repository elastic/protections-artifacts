rule Windows_VulnDriver_Compal_4d3269d0 {
    meta:
        author = "Elastic Security"
        id = "4d3269d0-b5c9-49ca-90c7-fba9bb432a53"
        fingerprint = "79aa1f63eaadb9025723e3533c037d64345ae66ba1a595d984d2d4fb2f44d91b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Compal electronic ,inc, Version: <= 2.0.0.2"
        threat_name = "Windows.VulnDriver.Compal"
        reference_sample = "011df46e94218cbb2f0b8da13ab3cec397246fdc63436e58b1bf597550a647f6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 6F 6D 70 61 6C 20 65 6C 65 63 74 72 6F 6E 69 63 20 2C 69 6E 63 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "TPwSav.pdb"
        $str2 = "IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Compal_5eea874d {
    meta:
        author = "Elastic Security"
        id = "5eea874d-ae84-48a6-8d5b-10f3289e6ce0"
        fingerprint = "c38a1199018ab6bb527cb4ea919415d577925ad63c934fa7a27d254dfe4d1ea6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Compal electronic ,inc, Version: <= 1.0.0.32"
        threat_name = "Windows.VulnDriver.Compal"
        reference_sample = "d7833a5d77ab264572458a51226000190857f1b5807c556e23e18c39bb950ca6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 6F 6D 70 61 6C 20 65 6C 65 63 74 72 6F 6E 69 63 20 2C 69 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 6F 00 4D 00 61 00 6E 00 61 00 67 00 65 00 72 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x1f][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x20-\x20][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "WTDMIOMngr.pdb"
        $str2 = "Compal IoManager Application" wide
        $str3 = "IoManager Application" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

