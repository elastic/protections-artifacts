rule Windows_VulnDriver_PcHunter_8ae31aa1 {
    meta:
        author = "Elastic Security"
        id = "8ae31aa1-3e5d-49dc-acda-b50d099a7b3a"
        fingerprint = "6f052077ebbc754acbdd11ffe3568f3496088cebea6f6005ab0926fa5e44d079"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 一普明为(北京)信息技术有限公司, Version: <= 1.0.0.4"
        threat_name = "Windows.VulnDriver.PcHunter"
        reference_sample = "1b7fb154a7b7903a3c81f12f4b094f24a3c60a6a8cffca894c67c264ab7545fa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B8 80 E6 99 AE E6 98 8E E4 B8 BA 28 E5 8C 97 E4 BA AC 29 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 43 00 48 00 75 00 6E 00 74 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x03][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "View++_Driver64.pdb"
        $str2 = "PCHunter" wide
        $str3 = "Epoolsoft Windows Information View Tools" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_PcHunter_19703bb1 {
    meta:
        author = "Elastic Security"
        id = "19703bb1-c0ab-4e9c-8743-cb508f33d7c0"
        fingerprint = "d538ec0329a69c0e89991bff8f06c25f8157c137849fcdfd35f0bfe67e4fab70"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 安芯网盾（北京）科技有限公司, Version: <= 1.0.5.7"
        threat_name = "Windows.VulnDriver.PcHunter"
        reference_sample = "3f20ac5dac9171857fc5791865458fdb6eac4fab837d7eabc42cb0a83cb522fc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 AE 89 E8 8A AF E7 BD 91 E7 9B BE EF BC 88 E5 8C 97 E4 BA AC EF BC 89 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x05-\x05][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = { FB 7C DF 7E E1 4F 6F 60 E5 67 0B 77 E5 5D 77 51 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

