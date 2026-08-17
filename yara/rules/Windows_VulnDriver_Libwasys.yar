rule Windows_VulnDriver_Libwasys_0b74345a {
    meta:
        author = "Elastic Security"
        id = "0b74345a-52be-4578-9bd1-83891ebc8309"
        fingerprint = "6b45e6c04981c78d303fc1349c72401beaa18c0ca75ab023f5bc7f9a91e0ade5"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: OPSWAT, Inc., Version: <= 10.3.85.0"
        threat_name = "Windows.VulnDriver.Libwasys"
        reference_sample = "04fda396f42384d9295fe306336ee4a685a0c341debdc27ddf9169f0336b46a6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 50 53 57 41 54 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6C 00 69 00 62 00 77 00 61 00 73 00 79 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x54][\x00-\x00]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x55-\x55][\x00-\x00])/
        $str1 = "LibWasys.pdb"
        $str2 = "OESIS V4 Kernel Driver" wide
        $str3 = "OESIS V4 Helper Driver (x64)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Libwasys_3da7c366 {
    meta:
        author = "Elastic Security"
        id = "3da7c366-6bd6-48db-a163-c58de24bbd9e"
        fingerprint = "26ee91320b2af30ce68828e999c62dd6a7d53ed97a0a8513ce0d4b1c496c5d8f"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: libwasys.sys, Version: <= 10.3.26.2"
        threat_name = "Windows.VulnDriver.Libwasys"
        reference_sample = "6f91bd4935ec882b1278682530bc8ff47acec55a67f524038175afdd5ed8dec4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6C 00 69 00 62 00 77 00 61 00 73 00 79 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x19][\x00-\x00]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x01][\x00-\x00][\x1a-\x1a][\x00-\x00]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x02-\x02][\x00-\x00][\x1a-\x1a][\x00-\x00])/
        $str1 = "LibWasys.pdb"
        $str2 = "OESIS V4 Kernel Driver" wide
        $str3 = "OESIS V4 Helper Driver (x64)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

