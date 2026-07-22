rule Windows_VulnDriver_Jinxian_f884c7a6 {
    meta:
        author = "Elastic Security"
        id = "f884c7a6-1558-49ae-b17e-ce56039201c2"
        fingerprint = "e0897176bc2db28442bd8f9493d1bae8289951f25d08b99e192f5ac15a7f5eb0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Shenzhen Jinxian Technology Co., Ltd."
        threat_name = "Windows.VulnDriver.Jinxian"
        reference_sample = "89036534a3da657882da96d9f211ae41efab4083bd6dbedbeaa2516d1d04cff4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 4A 69 6E 78 69 61 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "DriverInject.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

