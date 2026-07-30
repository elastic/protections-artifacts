rule Windows_VulnDriver_ShiruiElectronics_ccf646ac {
    meta:
        author = "Elastic Security"
        id = "ccf646ac-ac08-4189-9bda-4c33b4a4f2ab"
        fingerprint = "daa1cfc11315b992957eeacd22d72d9afb29071ab4d87802899ba1cb6fa7b5ea"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Guangzhou Shirui Electronics Co., Ltd"
        threat_name = "Windows.VulnDriver.ShiruiElectronics"
        reference_sample = "42322b59f75f3ee3f66d080433c01fe024ca9ce5cbd3acac8a98394ac2a0d659"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 75 61 6E 67 7A 68 6F 75 20 53 68 69 72 75 69 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 6F 2E 2C 20 4C 74 64 }
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_ShiruiElectronics_9da0976f {
    meta:
        author = "Elastic Security"
        id = "9da0976f-fcbd-400f-97ce-4940e30ecc6b"
        fingerprint = "48cda3a3a6964e0d4aba1417610211fd4ff5c0daa9bed6e6e42f50edb98c3aca"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Guangzhou Shirui Electronics Co., Ltd., Version: <= 0.0.1.6"
        threat_name = "Windows.VulnDriver.ShiruiElectronics"
        reference_sample = "4cea52c32579869d0209f18ced0b9cc9ad8f86cac29e0fb63b3d60eb64801bda"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 75 61 6E 67 7A 68 6F 75 20 53 68 69 72 75 69 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "WinCPUoC64.pdb"
        $str2 = "Windows CPU Temperature Component" wide
        $str3 = "seewo - Windows CPU Temperature Component" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

