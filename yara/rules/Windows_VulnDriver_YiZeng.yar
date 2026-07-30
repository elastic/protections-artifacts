rule Windows_VulnDriver_YiZeng_a14e301e {
    meta:
        author = "Elastic Security"
        id = "a14e301e-0c7f-4d31-a912-e5398ae9a3cd"
        fingerprint = "6a2b5565d02706df8c74ece43b4a3fcb9454e4ffb34dbb4b6cf75a5e5c4645c2"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: YI ZENG"
        threat_name = "Windows.VulnDriver.YiZeng"
        reference_sample = "56066ed07bad3b5c1474e8fae5ee2543d17d7977369b34450bd0775517e3b25c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 59 49 20 5A 45 4E 47 }
        $str1 = "nullout.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

