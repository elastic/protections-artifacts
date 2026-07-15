rule Windows_VulnDriver_EVGA_1a8123b5 {
    meta:
        author = "Elastic Security"
        id = "1a8123b5-6202-4239-a4af-10e72f66a57c"
        fingerprint = "88ad5b7df7e68cee67a7542920a38b81193d66d3d8720ed0d16b91fd45605730"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EVGA Corp., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.EVGA"
        reference_sample = "33da2ce240b4559cc6e847d56c5fbeaa3d644ec160841920ea0a098dcee28d0e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 56 47 41 20 43 6F 72 70 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "EVGA Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_EVGA_8ef13dae {
    meta:
        author = "Elastic Security"
        id = "8ef13dae-b827-4f04-97ae-56a553443947"
        fingerprint = "4cb3e60e93238d526220efa3a42de1ceaf69f7eeda987a4e81d2e6ed88bd7445"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EVGA, Version: <= 5.13.1.2008"
        threat_name = "Windows.VulnDriver.EVGA"
        reference_sample = "3c95ebf3f1a87f67d2861dbd1c85dc26c118610af0c9fbf4180428e653ac3e50"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 56 47 41 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 4D 00 41 00 52 00 54 00 45 00 49 00 4F 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0c][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0d-\x0d][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x0d-\x0d][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xd7][\x07-\x07])[\x01-\x01][\x00-\x00]|[\x0d-\x0d][\x00-\x00][\x05-\x05][\x00-\x00][\xd8-\xd8][\x07-\x07][\x01-\x01][\x00-\x00])/
        $str1 = "SMARTEIO64.pdb"
        $str2 = "Windows Vista64 Smart IO Device" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

