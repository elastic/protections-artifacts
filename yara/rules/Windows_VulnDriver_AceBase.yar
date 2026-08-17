rule Windows_VulnDriver_AceBase_f9ef7f72 {
    meta:
        author = "Elastic Security"
        id = "f9ef7f72-5bf1-4090-a32b-b009a2784d1a"
        fingerprint = "79878b4f3ba85c2e3fbe262a480b95b1fa116c21da5c26f5fc0ddeaf32ac3736"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: HIGH MORALE DEVELOPMENTS LIMITED, Version: <= 1.0.2202.6217"
        threat_name = "Windows.VulnDriver.AceBase"
        reference_sample = "7326aefff9ea3a32286b423a62baebe33b73251348666c1ee569afe62dd60e11"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 49 47 48 20 4D 4F 52 41 4C 45 20 44 45 56 45 4C 4F 50 4D 45 4E 54 53 20 4C 49 4D 49 54 45 44 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x99][\x08-\x08])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x17]|[\x00-\x48][\x18-\x18])[\x9a-\x9a][\x08-\x08]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x49-\x49][\x18-\x18][\x9a-\x9a][\x08-\x08])/
        $str1 = "ACE-BASE.pdb"
        $str2 = "Anti-Cheat Expert" wide
        $str3 = "ACE-BASE64 NT Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_AceBase_01b4cde0 {
    meta:
        author = "Elastic Security"
        id = "01b4cde0-aa2f-4ac4-8b41-ba0bef10ae07"
        fingerprint = "b5eecf8d3334763701a78b4faa5f3d94639734b0fa1d73c238f3afe15de83e9a"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: HIGH MORALE DEVELOPMENTS LIMITED, Version: <= 1.0.2306.11560"
        threat_name = "Windows.VulnDriver.AceBase"
        reference_sample = "0184b8314b3ddb11dd929b3ad9e4302f8246e99027077e42d7fc14b25d799428"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 49 47 48 20 4D 4F 52 41 4C 45 20 44 45 56 45 4C 4F 50 4D 45 4E 54 53 20 4C 49 4D 49 54 45 44 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x08]|[\x00-\x01][\x09-\x09])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x2c]|[\x00-\x27][\x2d-\x2d])[\x02-\x02][\x09-\x09]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x28-\x28][\x2d-\x2d][\x02-\x02][\x09-\x09])/
        $str1 = "ACE-BASE.pdb"
        $str2 = "Anti-Cheat Expert" wide
        $str3 = "ACE-BASE64 NT Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

