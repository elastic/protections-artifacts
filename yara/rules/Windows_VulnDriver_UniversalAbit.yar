rule Windows_VulnDriver_UniversalAbit_8f9646f1 {
    meta:
        author = "Elastic Security"
        id = "8f9646f1-b7fd-44d9-8e22-7352aa6c0e7a"
        fingerprint = "669e94e2c9de1f6f5cd1279d400f7d4ac621635c2565ab91524b663f63e0ffca"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Universal ABIT Co., Ltd."
        threat_name = "Windows.VulnDriver.UniversalAbit"
        reference_sample = "8797d9afc7a6bb0933f100a8acbb5d0666ec691779d522ac66c66817155b1c0d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 55 6E 69 76 65 72 73 61 6C 20 41 42 49 54 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "WinFlash64.pdb"
        $str2 = "\\Device\\WinFlash"
        $str3 = "\\DosDevices\\WinFlash"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

