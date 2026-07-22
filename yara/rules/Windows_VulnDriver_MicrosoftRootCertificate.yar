rule Windows_VulnDriver_MicrosoftRootCertificate_fb70edf6 {
    meta:
        author = "Elastic Security"
        id = "fb70edf6-cd8a-4838-a74d-16bd33b352f8"
        fingerprint = "3a71b0297f52dbf89fcfe2e9414e268bd5aefeb93731b9d71029c312ef3e8477"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.MicrosoftRootCertificate"
        reference_sample = "16b6be03495a4f4cf394194566bb02061fba2256cc04dcbde5aa6a17e41b7650"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "netfilterdrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_MicrosoftRootCertificate_17534d99 {
    meta:
        author = "Elastic Security"
        id = "17534d99-4c27-4a5b-b7d1-591c2a76acc9"
        fingerprint = "4384f5560102b8b1f1a0fdb6e9d44f92f33279fae587a73e50dbc8e49d06c9b5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.MicrosoftRootCertificate"
        reference_sample = "1afa03118f87b62c59a97617e595ebb26dde8dbdd16ee47ef3ddd1097c30ef6a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "AsIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_MicrosoftRootCertificate_f00874d7 {
    meta:
        author = "Elastic Security"
        id = "f00874d7-c072-495c-8e7f-c2ca5813ceab"
        fingerprint = "f951371a4a83508ead8f86c3bc9c5418ebe4ad3a946a56849d5991d786da9388"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows"
        threat_name = "Windows.VulnDriver.MicrosoftRootCertificate"
        reference_sample = "6071db01b50c658cf78665c24f1d21f21b4a12d16bfcfaa6813bf6bbc4d0a1e8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 }
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_PAGE_ALLOC_SIZE_IN"
        $str3 = "IOCTL_LOW_ALLOC_SIZE_IN"
        $str4 = "RTLogSetDefaultInstanceThread"
        $str5 = "RTSemEventMultiWaitNoResume"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_MicrosoftRootCertificate_0aa1bd1e {
    meta:
        author = "Elastic Security"
        id = "0aa1bd1e-2ed5-4b3d-a6bf-e5d89306d98e"
        fingerprint = "ec46e98aeafcc52cbc8fb71ab8a698c32c2894bf25971199de4af49264f3f34b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.MicrosoftRootCertificate"
        reference_sample = "9bb09752cf3a464455422909edef518ac18fe63cf5e1e8d9d6c2e68db62e0c87"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "FVTProect32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

