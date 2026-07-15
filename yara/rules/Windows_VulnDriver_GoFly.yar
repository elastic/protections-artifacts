rule Windows_VulnDriver_GoFly_c2fde977 {
    meta:
        author = "Elastic Security"
        id = "c2fde977-51ae-4cb1-994c-ce7579e5504e"
        fingerprint = "8033e48f16c525d28acdeb0c4ad3c32c83bbf84af134a87241fa03f42d374bf0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 南京偲言睿网络科技有限公司"
        threat_name = "Windows.VulnDriver.GoFly"
        reference_sample = "19116583316bcafcad9ffc5571ae86399f1e2f2a593f17d441febe2f1ff2c3ad"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 8D 97 E4 BA AC E5 81 B2 E8 A8 80 E7 9D BF E7 BD 91 E7 BB 9C E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "GoFly64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

