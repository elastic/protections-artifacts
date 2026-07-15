rule Windows_VulnDriver_Dangeroussig_af5a7b25 {
    meta:
        author = "Elastic Security"
        id = "af5a7b25-6ac1-4ed6-b799-69daf3b2ae02"
        fingerprint = "5dfb740a6c17690692f4cd1d3340fb8c27270ceea1a6d1da135d54f86f9e6ece"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 北京融汇画方科技有限公司, Version: <= 10.0.0.2"
        threat_name = "Windows.VulnDriver.Dangeroussig"
        reference_sample = "cf16a2218fc8a3b6fa5aa4a0bc6205792798078c380ccc7e5041476e0f1bc53d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 8C 97 E4 BA AC E8 9E 8D E6 B1 87 E7 94 BB E6 96 B9 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NetFlt.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

