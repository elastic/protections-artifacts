rule Windows_VulnDriver_SafeNet_7fd6c0cb {
    meta:
        author = "Elastic Security"
        id = "7fd6c0cb-d847-478c-b1eb-19e53726e315"
        fingerprint = "43f6155a2ac62db9a22d749c93b4dfb2393a06e939cee8ba381a0e5353a8aad1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SafeNet, Inc., Version: <= 4.0.16.0"
        threat_name = "Windows.VulnDriver.SafeNet"
        reference_sample = "07b6d69bafcfd767f1b63a490a8843c3bb1f8e1bbea56176109b5743c8f7d357"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 66 65 4E 65 74 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 6F 00 73 00 74 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0f][\x00-\x00]|[\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x10-\x10][\x00-\x00])/
        $str1 = "HOSTNT.pdb"
        $str2 = "Hostnt 64-bit driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

