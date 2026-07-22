rule Windows_VulnDriver_Pinchins_77a97ba9 {
    meta:
        author = "Elastic Security"
        id = "77a97ba9-c8cc-46ce-94db-41174c663c78"
        fingerprint = "cba5576c8ed7d0abfd854494030ebc9ac4dac7a62f2025fcb464c30b419975ac"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Pinchins Technology Company Limited, Version: <= 1.0.0.1006"
        threat_name = "Windows.VulnDriver.Pinchins"
        reference_sample = "1a74c2bde0c9a76486657ccb9c79ea87c9891a32cdd4aa15c7542f7c9487a539"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 69 6E 63 68 69 6E 73 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 6D 70 61 6E 79 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 57 00 54 00 4B 00 72 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xed][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xee-\xee][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "RWTKrl.pdb"
        $str2 = "RansomwareTerminator" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Pinchins_6844a79c {
    meta:
        author = "Elastic Security"
        id = "6844a79c-86b4-4888-b2cf-af39d39dda78"
        fingerprint = "93175f4b9e27bbbd1b3496d4205549fe2b8a0180ef18bd70f2cae28804ce012a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Pinchins Technology Company Limited, Version: <= 6.32.3.80"
        threat_name = "Windows.VulnDriver.Pinchins"
        reference_sample = "77225a99b2e0e2b4007fb2f5a96d356e13deab45b9ef54c175d5452de8a211a7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 69 6E 63 68 69 6E 73 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 6D 70 61 6E 79 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 64 00 6D 00 74 00 64 00 69 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1f][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x4f][\x00-\x00][\x03-\x03][\x00-\x00]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x50-\x50][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "Internet Download Manager" wide
        $str2 = "Internet Download Manager TDI Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Pinchins_cce86b0f {
    meta:
        author = "Elastic Security"
        id = "cce86b0f-1ed3-4c33-aa8e-eaef6d7a4fd0"
        fingerprint = "d135ade3a34b4f9ad2271cb6ece2cbc223fecc6af56f7bbeb749a3ccf8d3bb0e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Pinchins Technology Company Limited, Version: <= 1.0.0.808"
        threat_name = "Windows.VulnDriver.Pinchins"
        reference_sample = "930da474a6d1be97b54f2c81e883e14d62897aa58622e5b040e412bd36cee0a7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 69 6E 63 68 69 6E 73 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 6D 70 61 6E 79 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 57 00 54 00 4B 00 72 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x27][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x28-\x28][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "RansomwareTerminator" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

