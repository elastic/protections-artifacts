rule Windows_VulnDriver_Ardrv_cfcc9510 {
    meta:
        author = "Elastic Security"
        id = "cfcc9510-5edd-4ab5-8722-7901feea22d4"
        fingerprint = "7aa2e5a43f6bda23cfa3ccdb7de19f95bdd5bc77ee8aeda9a1bc910a7456109a"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: OPSWAT, Inc., Version: <= 2017.10.2.1551"
        threat_name = "Windows.VulnDriver.Ardrv"
        reference_sample = "07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 50 53 57 41 54 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 72 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x0e][\x06-\x06])[\x02-\x02][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07][\x0f-\x0f][\x06-\x06][\x02-\x02][\x00-\x00])/
        $str1 = "ardrv.pdb"
        $str2 = "AppRemover Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Ardrv_3b859b12 {
    meta:
        author = "Elastic Security"
        id = "3b859b12-d42e-4ec9-9519-09db2a1b0fea"
        fingerprint = "667913bfbf3326a0591a13a109cc68a958a3706cecabc77080b187281aa09edc"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: LIMITS, Inc., Version: <= 2017.10.2.1551"
        threat_name = "Windows.VulnDriver.Ardrv"
        reference_sample = "0298fffd518465b773847db1a8f62ae944d85ad532c524d636336b72d475ebe2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 49 4D 49 54 53 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 72 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x0e][\x06-\x06])[\x02-\x02][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe1-\xe1][\x07-\x07][\x0f-\x0f][\x06-\x06][\x02-\x02][\x00-\x00])/
        $str1 = "artav.pdb"
        $str2 = "AppRemover Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Ardrv_0b197c9c {
    meta:
        author = "Elastic Security"
        id = "0b197c9c-e31f-41df-a822-505a29e32c25"
        fingerprint = "1cd5f4be32f4215cc4bc52d4a78dd5b63d39f6cd33fd5b8d7149a2ebea87c2df"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: ardrv.sys, Version: <= 2022.2.11.151"
        threat_name = "Windows.VulnDriver.Ardrv"
        reference_sample = "7d58338f7e5b4b77459835a2e057a07f81f72991a0e282d079fd5e227f68b5de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 72 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x02-\x02][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\x96][\x00-\x00][\x0b-\x0b][\x00-\x00]|[\x02-\x02][\x00-\x00][\xe6-\xe6][\x07-\x07][\x97-\x97][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "ardrv.pdb"
        $str2 = "AppRemover Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

