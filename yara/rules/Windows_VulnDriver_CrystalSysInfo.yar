rule Windows_VulnDriver_CrystalSysInfo_81b6c47a {
    meta:
        author = "Elastic Security"
        id = "81b6c47a-93b5-4513-a6f6-113452e1fd83"
        fingerprint = "ca15fb3c5bf3fbfff4153de218b5ea721ee612238dffc0cc47fe5d008090cf7a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 飞依诺科技（苏州）有限公司"
        threat_name = "Windows.VulnDriver.CrystalSysInfo"
        reference_sample = "52c5ffd62eae04b890e0f4c96b84a3305e9b6571975c4352131cfc3d1b73a024"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 A3 9E E4 BE 9D E8 AF BA E7 A7 91 E6 8A 80 EF BC 88 E8 8B 8F E5 B7 9E EF BC 89 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "SysInfoX64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

