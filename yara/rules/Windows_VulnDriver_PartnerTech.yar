rule Windows_VulnDriver_PartnerTech_47712e65 {
    meta:
        author = "Elastic Security"
        id = "47712e65-40b3-41ab-b4e5-81820a155821"
        fingerprint = "8279fcc97c4eec119d8c78ee51d353025a1ed0762f168d1e0384a6c32b101c04"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech Corporation"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "0a6c37aa1d2d09f45078a22a9603f63dabc3ed33a3e1c27ae0baaa8ba0706757"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "WinIO64D.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_PartnerTech_3dd0e5d1 {
    meta:
        author = "Elastic Security"
        id = "3dd0e5d1-3779-4821-8301-818a6000dde8"
        fingerprint = "33dd35c1a53e36135caba0c493f5da090bc2b26d96ec686bd3fc160812d6b98a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "3c9b6da610e409f92f4f95f6f3f92a6e60e24903298a0e9af508f28e8c8962b6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WINIODrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_PartnerTech_1880f0c4 {
    meta:
        author = "Elastic Security"
        id = "1880f0c4-8868-4708-bcfd-1e14b89847dd"
        fingerprint = "5af2ce113a4c948aff668f324599508f1150409f604a069008cc205801c5a474"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "51e280cd9d1d84d43fab4a7be894804f24a1ca4d39f1df16fd8c60ea0a43b786"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WINIO_DISABLEDIRECTIO"
        $str3 = "IOCTL_WINIO_ENABLEDIRECTIO"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_PartnerTech_fcaf8fe7 {
    meta:
        author = "Elastic Security"
        id = "fcaf8fe7-8e6f-4509-9930-a5d04914cdd4"
        fingerprint = "f977496a0f1b9f97ebd770c7131d9df024675d9cf8fcc26bcc72159c593462ec"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "752565bab29cd2c63b4ff59a8c637bed02c2689781067ddf7cfc5c5221eb1d68"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WinIo64C.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_PartnerTech_640abd1f {
    meta:
        author = "Elastic Security"
        id = "640abd1f-e732-4d34-9423-41395d181bf3"
        fingerprint = "6ea18b4228672b14430dfa2ab87462fafd4d580e8850e0442bfcafb6927c17c5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd"
        threat_name = "Windows.VulnDriver.PartnerTech"
        reference_sample = "dc2b92f59fd8d059a58cc0761212f788d7041f708f4bd717d1738de909b4f781"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

