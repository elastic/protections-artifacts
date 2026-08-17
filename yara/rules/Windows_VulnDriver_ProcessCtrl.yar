rule Windows_VulnDriver_ProcessCtrl_adb62cb7 {
    meta:
        author = "Elastic Security"
        id = "adb62cb7-6f92-4587-bd43-386010ae947e"
        fingerprint = "a0d86ca050103bcd39538949898821c7634df1dfc709a5924a077c75e24fd2c2"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: 北京亿赛通科技发展有限责任公司, Version: <= 1.0.1.2"
        threat_name = "Windows.VulnDriver.ProcessCtrl"
        reference_sample = "d64eeb940daffdc8327fb18b160c20e539088cf8407813655f59efa9fdf0022e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 8C 97 E4 BA AC E4 BA BF E8 B5 9B E9 80 9A E7 A7 91 E6 8A 80 E5 8F 91 E5 B1 95 E6 9C 89 E9 99 90 E8 B4 A3 E4 BB BB E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 72 00 6F 00 63 00 65 00 73 00 73 00 43 00 74 00 72 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "ProcessCtrl64.pdb"
        $str2 = "ProcessCtrl" wide
        $str3 = "EsafeNet ProcessCtrl" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

