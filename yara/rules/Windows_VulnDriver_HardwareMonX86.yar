rule Windows_VulnDriver_HardwareMonX86_6844720d {
    meta:
        author = "Elastic Security"
        id = "6844720d-0f07-475d-8e0a-8b64a59adbb2"
        fingerprint = "1b2531fc0fbde801d44c447b81f11b1bd888cda0e2da252297ab982ae980fd90"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 湖北盛天网络技术股份有限公司, Version: <= 1.1.0.0"
        threat_name = "Windows.VulnDriver.HardwareMonX86"
        reference_sample = "14807ce592bf8f12da8a338d7ef575ae60c2d513c5c7ecf1f276aef3b2aa627c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 B9 96 E5 8C 97 E7 9B 9B E5 A4 A9 E7 BD 91 E7 BB 9C E6 8A 80 E6 9C AF E8 82 A1 E4 BB BD E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 61 00 72 00 64 00 77 00 61 00 72 00 65 00 4D 00 6F 00 6E 00 2D 00 78 00 38 00 36 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HardwareMon.pdb"
        $str2 = "Win I/O Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

