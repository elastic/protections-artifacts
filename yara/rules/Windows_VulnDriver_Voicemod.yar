rule Windows_VulnDriver_Voicemod_4b676430 {
    meta:
        author = "Elastic Security"
        id = "4b676430-6c81-4864-85a7-5045b2ff1946"
        fingerprint = "3ee274db27bf5ff42313c668d396710464c434ad516aa3349fd7f14b898101e0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Voicemod Sociedad Limitada, Version: <= 10.0.10011.16384"
        threat_name = "Windows.VulnDriver.Voicemod"
        reference_sample = "5c0b429e5935814457934fa9c10ac7a88e19068fa1bd152879e4e9b89c103921"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 56 6F 69 63 65 6D 6F 64 20 53 6F 63 69 65 64 61 64 20 4C 69 6D 69 74 61 64 61 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 6D 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x26]|[\x00-\x1a][\x27-\x27])|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3e]|[\x00-\xff][\x3f-\x3f])[\x1b-\x1b][\x27-\x27]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x40-\x40][\x1b-\x1b][\x27-\x27])/
        $str1 = "vmdrv.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "Voicemod Virtual Audio Device (WDM)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

