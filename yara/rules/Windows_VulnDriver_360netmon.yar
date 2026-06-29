rule Windows_VulnDriver_360netmon_cd62545a {
    meta:
        author = "Elastic Security"
        id = "cd62545a-97e7-41c8-bb36-ca7ad5503de2"
        fingerprint = "9cbd5f85cb8e506813c2b5ebc33319b5a8395ffc853151be829efc0951744ece"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.4.12.5300"
        threat_name = "Windows.VulnDriver.360netmon"
        reference_sample = "3d769a5f1ad0d32fb4e06478d35401d9788bad1a477b813adbdf4fd93b2c2694"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 33 00 36 00 30 00 6E 00 65 00 74 00 6D 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x04-\x04][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x13]|[\x00-\xb3][\x14-\x14])[\x0c-\x0c][\x00-\x00]|[\x04-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\xb4-\xb4][\x14-\x14][\x0c-\x0c][\x00-\x00])/
        $str1 = "360netmon_x64_wfp.pdb"
        $str2 = "360netmon" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

