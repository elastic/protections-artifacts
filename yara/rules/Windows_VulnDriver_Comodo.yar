rule Windows_VulnDriver_Comodo_3446897d {
    meta:
        author = "Elastic Security"
        id = "3446897d-dbee-45a2-a6f7-4bda10e8bd0c"
        fingerprint = "c5aa1502272a5c9fb1d84d2b31c8f15735f8afa522f0b7b8b17ef79831cde414"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Comodo Security Solutions, Inc., Version: <= 1.4.46817.49"
        threat_name = "Windows.VulnDriver.Comodo"
        reference_sample = "efbdd5de13be47fa7dd7689171c54725cf61f8efc7c2c9883321fc2c42b3eadc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 6F 6D 6F 64 6F 20 53 65 63 75 72 69 74 79 20 53 6F 6C 75 74 69 6F 6E 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 69 00 6C 00 6C 00 53 00 77 00 69 00 74 00 63 00 68 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xb5]|[\x00-\xe0][\xb6-\xb6])|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x30][\x00-\x00][\xe1-\xe1][\xb6-\xb6]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x31-\x31][\x00-\x00][\xe1-\xe1][\xb6-\xb6])/
        $str1 = "KillSwitch.pdb"
        $str2 = "KillSwitch" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

