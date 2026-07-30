rule Windows_VulnDriver_Zam_928812a7 {
    meta:
        author = "Elastic Security"
        id = "928812a7-ac7c-47cf-9111-11470b661d46"
        fingerprint = "8e5db0d4fee806538929680e7d3521b111b0e09fcc3eba3c191f6787375999cc"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb_64 = "AntiMalware\\bin\\zam64.pdb"
        $pdb_32 = "AntiMalware\\bin\\zam32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and any of ($pdb_*)
}

rule Windows_VulnDriver_Zam_7c86d260 {
    meta:
        author = "Elastic Security"
        id = "7c86d260-c571-4e99-83f9-5cd259e5c32e"
        fingerprint = "d1477b02d821893a5871c59a3c6c2c91e226daed9aa7f04a2c6f893fac05d419"
        creation_date = "2024-07-16"
        last_modified = "2024-09-30"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "6f55c148bb27c14408cf0f16f344abcd63539174ac855e510a42d78cfaec451c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 5A 00 41 00 4D 00 2E 00 65 00 78 00 65 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
        $s1 = "Advanced Malware Protection" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $s1
}

rule Windows_VulnDriver_Zam_8865a090 {
    meta:
        author = "Elastic Security"
        id = "8865a090-a765-43b4-86ed-e1fc37320cc4"
        fingerprint = "e684e7f7c2bddc7fdacc7f06c59f12c568b6d78f3b59c968b3a14fec95dfe76b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Yongji Zaihui E-commerce Co., Ltd., Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "03f41826ee5624e938ff9de7b621fc954decdf4b6f8cc266c43706881053c1ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 59 6F 6E 67 6A 69 20 5A 61 69 68 75 69 20 45 2D 63 6F 6D 6D 65 72 63 65 20 43 6F 2E 2C 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_9dcc58d1 {
    meta:
        author = "Elastic Security"
        id = "9dcc58d1-8f1a-49ab-a4e7-21b8fcdb7061"
        fingerprint = "fa803883574ba336ffecae29ec603088b0562032cfeafd3bd03ab9107098db7b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: CleverSoar Electronic Technology Co., Ltd., Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "078e7fb479ad6f0734682d41a17d41518de35bf4f6c5c212643b7d37e641041e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 6C 65 76 65 72 53 6F 61 72 20 45 6C 65 63 74 72 6F 6E 69 63 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_061934b9 {
    meta:
        author = "Elastic Security"
        id = "061934b9-a09f-44fa-beaf-b83d0938a10c"
        fingerprint = "a70af3ba710745f89396da023a2efdcfb6e92f9a2e489e23f9f0d93de8edf85a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Open Source Developer, Anqi Tao, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "090ca9a1f83b1e481b939922009d2c80b6c0be2b69003db5ce181b6954be249e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 41 6E 71 69 20 54 61 6F }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_f503bf43 {
    meta:
        author = "Elastic Security"
        id = "f503bf43-c2d2-4ddf-8330-91be4b2bb321"
        fingerprint = "da16d7c869c6c8cc631806ea1980051065e08a7c044db394fc1b1bb8269040bb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Open Source Developer, Mei Dong, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "1ff10fe592c4349de7460724735d8f3d0046f658f9b6a9ca77573a8da870d79b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 4D 65 69 20 44 6F 6E 67 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_592fae36 {
    meta:
        author = "Elastic Security"
        id = "592fae36-31b1-4831-bf26-5f35613ccca3"
        fingerprint = "5fbea95a8308f38095122e434f590920db627e07e3d0b6557de2bca5a9fbcc51"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Open Source Developer, 梅 董, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "34889b1763b1686a3914961242ee958f5ff5c61c8b990c50992ad535c407725f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 E6 A2 85 20 E8 91 A3 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_316a045d {
    meta:
        author = "Elastic Security"
        id = "316a045d-9a46-44e6-8340-8dc3163cd72d"
        fingerprint = "5881437982ff151cda012ec6b90ab898bf04230c3aeaec1c853f833b12e25f65"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 2.74.0.259"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "40b62ba97ba2edd3e01ed62d26ae8c09f36144ab33db18b42e5f1ccf82db1754"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 5A 00 41 00 4D 00 2E 00 65 00 78 00 65 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x49][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x4a-\x4a][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x02][\x01-\x01])[\x00-\x00][\x00-\x00]|[\x4a-\x4a][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x01-\x01][\x00-\x00][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_d0430420 {
    meta:
        author = "Elastic Security"
        id = "d0430420-4849-4d7e-a82d-4fec6b139e2d"
        fingerprint = "a96bd5fa635d3257f41bb60fd147ba8db1e295df471c301175a2c2d1d3fc2e71"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Open Source Developer, Gui Hu, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "47ae23519fb15a5992f75c6f16ff1abdb92397607e0ca60a3ee37c39f5e16cd3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 47 75 69 20 48 75 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_c46a5120 {
    meta:
        author = "Elastic Security"
        id = "c46a5120-3758-4d64-b61b-b036d7a31032"
        fingerprint = "4e492a476889190705a863d395c1068d40492446d7cd33937449d38d83365676"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Open Source Developer, Jiawu Wang, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "5dc63f4b6987b65bb4172c02ba024cb415ed9defd060fe628a46cb34271a1c42"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 4A 69 61 77 75 20 57 61 6E 67 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_5f89a617 {
    meta:
        author = "Elastic Security"
        id = "5f89a617-d2a7-4347-b247-6998e02ba831"
        fingerprint = "1d6d7d978b9493fef311a2e60bf505537107209ba518c67e8c394f08f7b9f146"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: ZAM.exe, Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "a3908b3fa59c0fc7600ff8887a87861a4f8566ca0a3bdcf2371bb9f36745db91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 5A 00 41 00 4D 00 2E 00 65 00 78 00 65 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
        $str4 = "Advanced Malware Protection" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Zam_cffca6e7 {
    meta:
        author = "Elastic Security"
        id = "cffca6e7-ca67-4490-a796-0c6b93ca19b4"
        fingerprint = "f06a9ebb4f032493c787bafcba61d7589bc98995593e10472abe02e61afd503b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "ab2632a4d93a7f3b7598c06a9fdc773a1b1b69a7dd926bdb7cf578992628e9dd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam32.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zam_0fddb921 {
    meta:
        author = "Elastic Security"
        id = "0fddb921-8caf-42cb-b5e3-30f3b45ae328"
        fingerprint = "350bd1810e37abd2699dc71ae5a98440852a3df0e93a453dce2f1f23379d66a6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 2.11.1.510"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "d7e091e0d478c34232e8479b950c5513077b3a69309885cee4c61063e5f74ac0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0a][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0b-\x0b][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x0b-\x0b][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xfd][\x01-\x01])[\x01-\x01][\x00-\x00]|[\x0b-\x0b][\x00-\x00][\x02-\x02][\x00-\x00][\xfe-\xfe][\x01-\x01][\x01-\x01][\x00-\x00])/
        $str1 = "zam64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

rule Windows_VulnDriver_Zam_5e44a46c {
    meta:
        author = "Elastic Security"
        id = "5e44a46c-8589-4db8-b695-8ab46325cf7c"
        fingerprint = "2a43a2359cc64e837611da2faeca9d3ffaead49cfab817d3592c2ce83f23895a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 中船重工汉光科技股份有限公司, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Zam"
        reference_sample = "e8b6b76f9be9682efcce6f701707cfd4e401ea5bc089f2ceeda4ceea8b6c9a26"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B8 AD E8 88 B9 E9 87 8D E5 B7 A5 E6 B1 89 E5 85 89 E7 A7 91 E6 8A 80 E8 82 A1 E4 BB BD E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

