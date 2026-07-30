rule Windows_VulnDriver_Zuhaowan_64dd3300 {
    meta:
        author = "Elastic Security"
        id = "64dd3300-9031-4a48-a28f-245b3e1899cd"
        fingerprint = "363e34dd2e670f00e7c5d70a9b4a6fb3441bac91c4014ddc1ae17fe7c7ac8d40"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 安徽省刀锋网络科技有限公司"
        threat_name = "Windows.VulnDriver.Zuhaowan"
        reference_sample = "082d4d4d4ba1bda5e1599bd24e930ae9f000e7d12b00f7021cca90a4600ea470"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 AE 89 E5 BE BD E7 9C 81 E5 88 80 E9 94 8B E7 BD 91 E7 BB 9C E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "ProtectS.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

