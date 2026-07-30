rule Windows_VulnDriver_Symantec_7d07ca3a {
    meta:
        author = "Elastic Security"
        id = "7d07ca3a-285c-4587-99c9-d8efc0aecae2"
        fingerprint = "978194ab6932ff1f47263c10b728212def2de153a0353b352ffc2562be578097"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Symantec Corporation, Version: <= 1.0.0.45708"
        threat_name = "Windows.VulnDriver.Symantec"
        reference_sample = "7877c1b0e7429453b750218ca491c2825dae684ad9616642eff7b41715c70aca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 6D 61 6E 74 65 63 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 50 00 72 00 6F 00 45 00 76 00 65 00 6E 00 74 00 4D 00 6F 00 6E 00 69 00 74 00 6F 00 72 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xb1]|[\x00-\x8b][\xb2-\xb2])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x8c-\x8c][\xb2-\xb2][\x00-\x00][\x00-\x00])/
        $str1 = "VProEventMonitor.pdb"
        $str2 = "Symantec Event Monitors Driver Development Edition" wide
        $str3 = "VProEventMonitor.Sys - Event Monitoring driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

