rule Windows_VulnDriver_Sapphire_6f27d20e {
    meta:
        author = "Elastic Security"
        id = "6f27d20e-ac08-4d54-a839-43f672f047b3"
        fingerprint = "c0dfe395d3e0a7384fb67c1113cc942f9ef851b96fe48b039ded955ffb57ba39"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sapphire Technology Limited, Version: <= 1.60.0.0"
        threat_name = "Windows.VulnDriver.Sapphire"
        reference_sample = "6e7b28216c1d7f1dab6e147823c70414df804836701fa43ec686fd7f4a6e573f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 70 70 68 69 72 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 69 6D 69 74 65 64 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x3b][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x3c-\x3c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $version and $str1 and $str2
}

