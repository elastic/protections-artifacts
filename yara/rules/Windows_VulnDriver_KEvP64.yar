rule Windows_VulnDriver_KEvP64_0aaa2bc4 {
    meta:
        author = "Elastic Security"
        id = "0aaa2bc4-8a36-47ab-b38f-7c664a650d47"
        fingerprint = "b5b7defa43f4b52feef9b1687f146db2079b231e939f0a1eedd2eb1b412787e0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 北京华林保软件技术有限公司, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.KEvP64"
        reference_sample = "09b0e07af8b17db1d896b78da4dd3f55db76738ee1f4ced083a97d737334a184"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 8C 97 E4 BA AC E5 8D 8E E6 9E 97 E4 BF 9D E8 BD AF E4 BB B6 E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 45 00 76 00 50 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "kEvP64.pdb"
        $str2 = "PowerTool" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

