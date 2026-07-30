rule Windows_VulnDriver_VBox_3315863f {
    meta:
        author = "Elastic Security"
        id = "3315863f-668c-47ec-86c7-85d50c3b97d9"
        fingerprint = "b0aea1369943318246f1601f823c72f92a0155791661dadc4c854827c295e4bf"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: innotek GmbH"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "42d926cfb3794f9b1e3cb397498696cb687f505e15feb9df11b419c49c9af498"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Windows_VulnDriver_VBox_1b1c5cd5 {
    meta:
        author = "Elastic Security"
        id = "1b1c5cd5-23d3-4f1f-a396-3f2b18e28b64"
        fingerprint = "89dd35bb023ebc03c46c0e70ac975025921da289cb3374f2912fbb323c591bd9"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: VBoxDrv.sys, Version: 3.0.0.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "1684e24dae20ab83ab5462aa1ff6473110ec53f52a32cfb8c1fe95a2642c6d22"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_VBox_c3e681e1 {
    meta:
        author = "Elastic Security"
        id = "c3e681e1-9274-473e-ba7a-36a23c04a9ce"
        fingerprint = "56d375b7f4bef159e0c38ea47913f5f9d351eb9c23783c081cbcb9e44f350997"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Vektor T13 Security Service, Version: <= 1.2.0.19230"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "26f41e4268be59f5de07552b51fa52d18d88be94f8895eb4a16de0f3940cf712"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 56 65 6B 74 6F 72 20 54 31 33 20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x4a]|[\x00-\x1d][\x4b-\x4b])[\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x1e-\x1e][\x4b-\x4b][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_LOGGER_SETTINGS_SIZE_IN"
        $str3 = "IOCTL_PAGE_ALLOC_EX_SIZE_IN"
        $str4 = "RTMpOnPairIsConcurrentExecSupported"
        $str5 = "RTTimerReleaseSystemGranularity"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_57255830 {
    meta:
        author = "Elastic Security"
        id = "57255830-49e2-468a-9f10-dfa3699ce7c8"
        fingerprint = "fcd1554e360f647deba4951274d0f050fba6c93998f75e67436ba2d599613fa0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Vektor T13 Technology, Version: <= 1.4.2.19230"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "3724b39e97936bb20ada51c6119aded04530ed86f6b8d6b45fbfb2f3b9a4114b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 56 65 6B 74 6F 72 20 54 31 33 20 54 65 63 68 6E 6F 6C 6F 67 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x4a]|[\x00-\x1d][\x4b-\x4b])[\x02-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x1e-\x1e][\x4b-\x4b][\x02-\x02][\x00-\x00])/
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_LOGGER_SETTINGS_SIZE_IN"
        $str3 = "IOCTL_PAGE_ALLOC_EX_SIZE_IN"
        $str4 = "RTMpOnPairIsConcurrentExecSupported"
        $str5 = "RTTimerReleaseSystemGranularity"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_7ac976dd {
    meta:
        author = "Elastic Security"
        id = "7ac976dd-5cb8-40d2-8b22-6809c09f01c5"
        fingerprint = "998669c45e8ec0a1793b7f9af7b3beaadc8e8264053cab7048a25b560bf07e0b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: InnoTek Systemberatung GmbH, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "3d055be2671e136c937f361cef905e295ddb6983526341f1d5f80a16b7655b40"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 6E 6F 54 65 6B 20 53 79 73 74 65 6D 62 65 72 61 74 75 6E 67 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 55 00 53 00 42 00 4D 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxUSBMon.pdb"
        $str2 = "\\Device\\USBPDO-%d"
        $str3 = "AssertMsg1"
        $str4 = "VirtualBox USB Monitor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_VBox_d1d1ce96 {
    meta:
        author = "Elastic Security"
        id = "d1d1ce96-ec53-4d5f-9cbb-910bab27dba7"
        fingerprint = "3e92a1cb1dec8486e46ee63ecadb15589a087079fb12a4d046f143ee0f690073"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: innotek GmbH, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "5b26c4678ecd37d1829513f41ff9e9df9ef1d1d6fea9e3d477353c90cc915291"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 55 00 53 00 42 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxUSB.pdb"
        $str2 = "AssertMsg1"
        $str3 = "VirtualBox USB driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_VBox_80a456c7 {
    meta:
        author = "Elastic Security"
        id = "80a456c7-070f-4a2e-9eac-8c77dec3bfdb"
        fingerprint = "ab9c8c092617d881f651d8a7a4f3fabe0a12342c35f04ec6e979f3e96378b505"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: innotek GmbH"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "73fddd441a764e808ed6d6b8f3d0d13713e61221aa3cfef7da91cdaf112fe061"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_PAGE_ALLOC_SIZE_IN"
        $str3 = "IOCTL_LOW_ALLOC_SIZE_IN"
        $str4 = "RTLogSetDefaultInstanceThread"
        $str5 = "RTSemEventMultiWaitNoResume"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_2b119c8d {
    meta:
        author = "Elastic Security"
        id = "2b119c8d-e66d-4168-927c-206ae789395b"
        fingerprint = "9d233017c1f49d2e907a8e21dca8d0eea2cdcaac709b3a76f63a532b468afd40"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sun Microsystems, Inc., Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "7539157df91923d4575f7f57c8eb8b0fd87f064c919c1db85e73eebb2910b60c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 6E 20 4D 69 63 72 6F 73 79 73 74 65 6D 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_LOGGER_SETTINGS_SIZE_IN"
        $str3 = "IOCTL_PAGE_ALLOC_EX_SIZE_IN"
        $str4 = "RTTimerReleaseSystemGranularity"
        $str5 = "RTTimerRequestSystemGranularity"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_d43f5fe3 {
    meta:
        author = "Elastic Security"
        id = "d43f5fe3-cc99-4fe1-8444-712df49a16d3"
        fingerprint = "64f1dda453d4d1093b16060b6c2159dda148250263e72a5378d22755b9a5cb70"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: innotek GmbH, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "8a2482e19040d591c7cec5dfc35865596ce0154350b5c4e1c9eecc86e7752145"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 55 00 53 00 42 00 4D 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxUSBMon.pdb"
        $str2 = "\\Device\\USBPDO-%d"
        $str3 = "RTSpinlockAcquireNoInts"
        $str4 = "RTSpinlockReleaseNoInts"
        $str5 = "VirtualBox USB Monitor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_f4df8195 {
    meta:
        author = "Elastic Security"
        id = "f4df8195-0567-4b2c-be3a-0a85bed360f1"
        fingerprint = "cc8f6792e792ed027126bfc9d09d3fb1e02b07d3e7f0c55ab02c9ff49ab81807"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: InnoTek Systemberatung GmbH, Version: <= 1.5.0.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "983310cdce8397c016bfcfcc9c3a8abbb5c928b235bc3c3ae3a3cc10ef24dfbd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 6E 6F 54 65 6B 20 53 79 73 74 65 6D 62 65 72 61 74 75 6E 67 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 62 00 6F 00 78 00 67 00 75 00 65 00 73 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxGuest.pdb"
        $str2 = "RTSemFastMutexDestroy"
        $str3 = "RTSemFastMutexRelease"
        $str4 = "VirtualBox Guest Additions" wide
        $str5 = "VirtualBox Guest Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_139ce083 {
    meta:
        author = "Elastic Security"
        id = "139ce083-3913-42f8-a0d4-cca5e78411db"
        fingerprint = "a71c0ffcfac5d5753d8e73f9fabb336cdee8d34c23ae5440a84dfbf6ee2ff2fe"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: InnoTek Systemberatung GmbH, Version: <= 8.0.0.2"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "994f322def98c99aec7ea0036ef5f4b802120458782ae3867d116d55215c56e4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 6E 6F 54 65 6B 20 53 79 73 74 65 6D 62 65 72 61 74 75 6E 67 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 54 00 41 00 50 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxTAP.pdb"
        $str2 = "\\DosDevices\\Global\\"
        $str3 = "VirtualBox Host Interface Networking Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_VBox_29257e81 {
    meta:
        author = "Elastic Security"
        id = "29257e81-91f9-46ba-8c80-57e7bd1274d3"
        fingerprint = "d0eff2e0f34b6bd21cc50e258455979b793c7f12a5d635a84996354d2da11066"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Huiping Zhong, Version: <= 1.2.0.37904"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "9dab4b6fddc8e1ec0a186aa8382b184a5d52cfcabaaf04ff9e3767021eb09cf4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 69 70 69 6E 67 20 5A 68 6F 6E 67 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x93]|[\x00-\x0f][\x94-\x94])[\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x10-\x10][\x94-\x94][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_LOGGER_SETTINGS_SIZE_IN"
        $str3 = "IOCTL_PAGE_ALLOC_EX_SIZE_IN"
        $str4 = "RTCrX509AlgorithmIdentifier_CompareDigestOidAndEncryptedDigestOid"
        $str5 = "RTCrX509AlgorithmIdentifier_CombineEncryptionOidAndDigestOid"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_af569000 {
    meta:
        author = "Elastic Security"
        id = "af569000-d3d4-4fee-b9ee-99144b7e7fad"
        fingerprint = "1378f67c2df4f1191c60f160dcc4a397ccbf948bb89739ac64617caf9e461c32"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: innotek GmbH, Version: <= 1.5.6.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "bbf564a02784d53b8006333406807c3539ee4a594585b1f3713325904cb730ec"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 4D 00 6F 00 75 00 73 00 65 00 4E 00 54 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "VBoxMouseNT.pdb"
        $str2 = "RTSemFastMutexDestroy"
        $str3 = "RTSemFastMutexRelease"
        $str4 = "VirtualBox Guest Additions" wide
        $str5 = "VirtualBox i8042 Port Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_58185b47 {
    meta:
        author = "Elastic Security"
        id = "58185b47-e0a8-471c-a9f6-c1ffb1db45d1"
        fingerprint = "4c3de1c51e400f81e39fe85b390c740b0bec37a530cbee482f9294b23a2f76c6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: InnoTek Systemberatung GmbH, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "c509935f3812ad9b363754216561e0a529fc2d5b8e86bfa7302b8d149b7d04aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 6E 6F 54 65 6B 20 53 79 73 74 65 6D 62 65 72 61 74 75 6E 67 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 55 00 53 00 42 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxUSB.pdb"
        $str2 = "AssertMsg1"
        $str3 = "VirtualBox USB driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_VBox_f7baf5ed {
    meta:
        author = "Elastic Security"
        id = "f7baf5ed-9d6c-448c-a290-8e79b47e6bed"
        fingerprint = "6dfa480153a08d1a96e0daeb1f93ab3a498d66a39bab546ba779495d6f3163b3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: innotek GmbH, Version: <= 8.0.0.2"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "cfa28e2f624f927d4cbd2952306570d86901d2f24e3d07cc6277e98289d09783"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 54 00 41 00 50 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VBoxTAP.pdb"
        $str2 = "\\DosDevices\\Global\\"
        $str3 = "VirtualBox Host Interface Networking Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_VBox_bfba155d {
    meta:
        author = "Elastic Security"
        id = "bfba155d-25b9-4bd2-b5e8-de80d19b9cc9"
        fingerprint = "d43cd5e0d47daacce758477b95743c03a0cbf66806ef6f2ef7e75a5b23961098"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: innotek GmbH, Version: <= 1.5.6.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "d53f9111a5e6c94b37e3f39c5860897405cb250dd11aa91c3814a98b1759c055"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 62 00 6F 00 78 00 67 00 75 00 65 00 73 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "VBoxGuestNT.pdb"
        $str2 = "RTSemFastMutexDestroy"
        $str3 = "RTSemFastMutexRelease"
        $str4 = "VirtualBox Guest Additions" wide
        $str5 = "VirtualBox Guest Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_VBox_7d17e264 {
    meta:
        author = "Elastic Security"
        id = "7d17e264-176f-416b-857a-40c74e75b017"
        fingerprint = "d417e973f3cdff4b534fba959f4d40906b015bd18e1e78655177fbfadb72ec53"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 4.3.12.0"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "e786f64dab69f2ae1e399044f59dc4b8efc7c291f77ca7f5df4394fe00edf62b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 4E 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x03-\x03][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00])/
        $str1 = "VBoxDrv.pdb"
        $str2 = "IOCTL_LOGGER_SETTINGS_SIZE_IN"
        $str3 = "IOCTL_PAGE_ALLOC_EX_SIZE_IN"
        $str4 = "RTTimerReleaseSystemGranularity"
        $str5 = "RTTimerRequestSystemGranularity"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

