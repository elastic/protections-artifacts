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

rule Windows_VulnDriver_Symantec_9a536ae6 {
    meta:
        author = "Elastic Security"
        id = "9a536ae6-0175-4af6-8d8c-0baf1a663c28"
        fingerprint = "b399d74e6ffab3e933cdd70a66c9f4c1a6c9e05dd1552485af70013aaff1582c"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Broadcom Inc, Version: <= 11.0.1.640"
        threat_name = "Windows.VulnDriver.Symantec"
        reference_sample = "02579d833200abb641e476468bafd1f07d448f3d232f70cc34e2adad402b5c75"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 72 6F 61 64 63 6F 6D 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 47 00 50 00 77 00 64 00 65 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\x7f][\x02-\x02])[\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00][\x80-\x80][\x02-\x02][\x01-\x01][\x00-\x00])/
        $str1 = "PGPwded.pdb"
        $str2 = "Symantec Encryption Desktop" wide
        $str3 = "PGPwde NT/Win2k driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Symantec_2a989e3c {
    meta:
        author = "Elastic Security"
        id = "2a989e3c-3f2c-41e1-b8bb-cf14c308e59b"
        fingerprint = "69c132b86f978330a2ec000682f64402c3ec59ed63cb6d50345ae36df2f9d26c"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Symantec Corporation, Version: <= 10.4.2.463"
        threat_name = "Windows.VulnDriver.Symantec"
        reference_sample = "5247d4ab237e8fc486ce95d018bd92074b2a8cf1af351cd699a5b4a9355c7071"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 6D 61 6E 74 65 63 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 47 00 50 00 77 00 64 00 65 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x04-\x04][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xce][\x01-\x01])[\x02-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x0a-\x0a][\x00-\x00][\xcf-\xcf][\x01-\x01][\x02-\x02][\x00-\x00])/
        $str1 = "PGPwded.pdb"
        $str2 = "Symantec Encryption Desktop" wide
        $str3 = "PGPwde NT/Win2k driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

