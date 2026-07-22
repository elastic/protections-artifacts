rule Windows_VulnDriver_NoriyukiMIYAZAKI_aecf2896 {
    meta:
        author = "Elastic Security"
        id = "aecf2896-a16c-4313-82d1-b8ab4b605ca7"
        fingerprint = "1f582ece12814dc6965e34af7704d5832e7468981d352915055d1708a62b35a4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Noriyuki MIYAZAKI"
        threat_name = "Windows.VulnDriver.NoriyukiMIYAZAKI"
        reference_sample = "4fea15aabc4fc63a3e991412caf17283bbd257172ef7e255f40f5e22e0286902"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 72 69 79 75 6B 69 20 4D 49 59 41 5A 41 4B 49 }
        $str1 = "SysInfo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_NoriyukiMIYAZAKI_6145433d {
    meta:
        author = "Elastic Security"
        id = "6145433d-f2ae-4a8e-b849-a15d18e4aedc"
        fingerprint = "544a9e691426b5be774cc0cfd3c217baab14acedb154eba609db797497d2121b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Noriyuki MIYAZAKI, Version: <= 1.0.1.3"
        threat_name = "Windows.VulnDriver.NoriyukiMIYAZAKI"
        reference_sample = "f0605dda1def240dc7e14efa73927d6c6d89988c01ea8647b671667b2b167008"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 72 69 79 75 6B 69 20 4D 49 59 41 5A 41 4B 49 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4F 00 70 00 65 00 6E 00 4C 00 69 00 62 00 53 00 79 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "OpenLibSys.pdb"
        $str2 = "OpenLibSys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

