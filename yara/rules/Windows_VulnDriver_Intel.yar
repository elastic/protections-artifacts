rule Windows_VulnDriver_Intel_2aa495f2 {
    meta:
        author = "Elastic Security"
        id = "2aa495f2-bd1e-4d47-bb75-619facb467e2"
        fingerprint = "856de428921d11b9400ee19600b929207b7b177f83893c77682a12b912890d14"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "11cf5a8c3a2cdd8df81e8c3e477bb84b25fb92becb41f35a5d675acaa1466890"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_1.pdb"
        $str2 = "IOCTL_GET_CHIPSET_DEVICE_ID"
        $str3 = "IOCTL_EM_CONFIG_NEXT_UNC"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_84f3973f {
    meta:
        author = "Elastic Security"
        id = "84f3973f-f8a4-48b8-aa91-72154f627fa3"
        fingerprint = "95f1d823d1d308f5becb15a989ef592b9b77fcf76e6905ab8362c0c2c3d776a8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Development Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "17f19350ea6715ce94ca2014bce92a5c07fd752fd06647a8200db6b052468810"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 44 65 76 65 6C 6F 70 6D 65 6E 74 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_15.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Intel_387d311e {
    meta:
        author = "Elastic Security"
        id = "387d311e-4d72-42fb-8a2a-7f424df9f811"
        fingerprint = "caa54b9e8b5283d8cf5b9a7f28f82771ced891d7b8714e0ab2c73de39459ca83"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 1.3.0.4"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "19bf0d0f55d2ad33ef2d105520bde8fb4286f00e9d7a721e3c9587b9408a0775"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x03][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "iqvw64.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_3975501f {
    meta:
        author = "Elastic Security"
        id = "3975501f-9939-4768-9892-8ae57610b212"
        fingerprint = "3346cbd43cf8d3a7151251cae1105f117cb3595527fd00a9e8e900635450ea83"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) INTELND1617S2, Version: <= 1.3.2.16"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "1f8168036d636aad1680dd0f577ef9532dbb2dad3591d63e752b0ba3ee6fd501"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 49 4E 54 45 4C 4E 44 31 36 31 37 53 32 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0f][\x00-\x00][\x02-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x10-\x10][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_89f8af9a {
    meta:
        author = "Elastic Security"
        id = "89f8af9a-0a1a-43ec-85f8-56b6285c1232"
        fingerprint = "0a997d878e8386ead19140d2062ddbadd11f2ed4232aaf4c9e482734fdcc087e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "321104460942bf98c5c248f660e068e5170c16ae8eedfa7acc5bf98471042a4e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "sepdrv3_15.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Intel_8ae31e4f {
    meta:
        author = "Elastic Security"
        id = "8ae31e4f-b5ac-4697-bf3d-5216ff34ef62"
        fingerprint = "af635c1cc58ec04f0d1cfec23e6c7d918aac310b1c298ef3405ab047ce270cf8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 2.0.0.0"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "37022838c4327e2a5805e8479330d8ff6f8cd3495079905e867811906c98ea20"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 74 00 64 00 63 00 64 00 72 00 76 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "stdcdrv64.pdb"
        $str2 = "SelfTest Data Collector" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Intel_1373ed9e {
    meta:
        author = "Elastic Security"
        id = "1373ed9e-2f8e-4a99-bf4f-0bf6d81294fe"
        fingerprint = "69df99c02d8185cc98ab6576a4c14c20c7a8589a2082bff3ad498fe835311e9d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "382cb4c37fdcb2e2ca9cbb4a5de39fa4e230d1d2e1b6f38e1c8249002525f1c7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "EnergyDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Intel_221a6d31 {
    meta:
        author = "Elastic Security"
        id = "221a6d31-1fab-4c62-aa02-8c119a1061a4"
        fingerprint = "58a6c7f39035be7b5d37217bb70bf984ab7fee9407f8b307fb1a6a133242fe3e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Tools and Technologies, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "3a2453ac5288505187d8dae35234ff2b0883f5d681146218ee4a2d7d6d8cddaf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 54 6F 6F 6C 73 20 61 6E 64 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 74 00 64 00 63 00 64 00 72 00 76 00 78 00 70 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "stdcdrvxp64.pdb"
        $str2 = "SelfTest Data Collector Driver for Windows x64" wide
        $str3 = "SelfTest Data Collector Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_ddc245ff {
    meta:
        author = "Elastic Security"
        id = "ddc245ff-7137-43a6-a8c6-b60081c776b3"
        fingerprint = "0a0626bbafc093236289a87ca756aeae7afabed983ce334ab43659546225ccbc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 1.3.0.7"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_ae20e083 {
    meta:
        author = "Elastic Security"
        id = "ae20e083-4415-416a-a7e0-fcafbf9add0b"
        fingerprint = "884f38a382f90cb117e1f4383801e3295262acd773420879f975a2f2df778dee"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "54fc3cad3fc4d45eaf43b96b175a65879761c996c4e26880064170811b0a11ff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_10.pdb"
        $str2 = "IOCTL_GET_CHIPSET_DEVICE_ID"
        $str3 = "IOCTL_WRITE_PCI_CONFIG"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_9035e9c7 {
    meta:
        author = "Elastic Security"
        id = "9035e9c7-2868-461d-82d1-a6e6fa8025fa"
        fingerprint = "02ece20ed6d623a9745169d7ea0bdc1b4e9ba33bb40f98cc62f6c42089b9b69a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) INTELND1617, Version: <= 1.3.2.13"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "5f6547e9823f94c5b94af1fb69a967c4902f72b6e0c783804835e6ce27f887b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 49 4E 54 45 4C 4E 44 31 36 31 37 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0c][\x00-\x00][\x02-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x0d-\x0d][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_273ec308 {
    meta:
        author = "Elastic Security"
        id = "273ec308-26e2-4a7f-8777-5d7e37ac3be5"
        fingerprint = "f2831676423889fe60939dd414247c97d9ee026c040cecea6cb7d341bb4e5070"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) INTELNPG1, Version: <= 1.3.2.7"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "5f69d6b167a1eeca3f6ac64785c3c01976ee7303171faf998d65852056988683"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 49 4E 54 45 4C 4E 50 47 31 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x02-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_2909f4e6 {
    meta:
        author = "Elastic Security"
        id = "2909f4e6-7c69-4667-92f8-b64b746f83d5"
        fingerprint = "edca7fa9e3ea5f53558c19b3d6d276c3d40ce54e15ee47c706dd6cf90b6d2d55"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: SEMA Software"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "648994905b29b9c4a1074eef332bf6932b638bad62df020b5452c74e2b15d78f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 45 4D 41 20 53 6F 66 74 77 61 72 65 }
        $str1 = "semav6msr64.pdb"
        $str2 = "IOCTL_SEMAV6MSR64_CLEAR_ONE"
        $str3 = "IOCTL_SEMAV6MSR64_WRITE_ONE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_a465883c {
    meta:
        author = "Elastic Security"
        id = "a465883c-880f-479e-9e8a-a57fb5de2d10"
        fingerprint = "72e4a43423cfc30a92ae7c3a1e00908e29a9f87be78d96210f6299ac397372d6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Tools and Technologies, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "70afdc0e11db840d5367afe53c35d9642c1cf616c7832ab283781d085988e505"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 54 6F 6F 6C 73 20 61 6E 64 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 74 00 64 00 63 00 64 00 72 00 76 00 77 00 73 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "stdcdrvws64.pdb"
        $str2 = "SelfTest Data Collector Driver for Windows 7 x64" wide
        $str3 = "SelfTest Data Collector Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_62b53d25 {
    meta:
        author = "Elastic Security"
        id = "62b53d25-6d97-449b-b066-b03ef51a4835"
        fingerprint = "a7d01573ac8698a841bcaf6a29c48bdd6e1211ef454210ad77326c15edc273b6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: ND_QV, Version: <= 1.3.2.18"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "7cb497abc44aad09a38160d6a071db499e05ff5871802ccc45d565d242026ee7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 44 5F 51 56 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x11][\x00-\x00][\x02-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x12-\x12][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_25452a88 {
    meta:
        author = "Elastic Security"
        id = "25452a88-82c2-420a-81f4-ee7778c2eccf"
        fingerprint = "ead0cd4385e17032ed229a87432875d6e497a783349fec55f3a5c30ecaa5dfff"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PAIPTAC  Driver"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "82b30461dbf40ac15fce6a83b9bad2ebd05b27dea1b784eaa096422fe8927b7b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 41 49 50 54 41 43 20 20 44 72 69 76 65 72 }
        $str1 = "pmxdrv32e.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Intel_7bff0772 {
    meta:
        author = "Elastic Security"
        id = "7bff0772-e9c5-452d-81fc-71dd96064b4e"
        fingerprint = "2ee6bcefd5c4b6a169f575f0b6a2a61d06c48908e52d2af319ebd0ab4cbbb2da"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 9.8.4.59"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "9a91d6e83b8fdec536580f6617f10dfc64eedf14ead29a6a644eb154426622ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 66 00 65 00 43 00 6F 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x08-\x08][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x3a][\x00-\x00][\x04-\x04][\x00-\x00]|[\x08-\x08][\x00-\x00][\x09-\x09][\x00-\x00][\x3b-\x3b][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "KfeCo11x64.pdb"
        $str2 = "Killer Traffic Control" wide
        $str3 = "Killer Traffic Control Callout Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_e36207b2 {
    meta:
        author = "Elastic Security"
        id = "e36207b2-fb3c-4b07-8136-5760d17b21b6"
        fingerprint = "885b7932a11786a4ae8d43ebcb50ab6951a8554d14a8fb7e77b03b2530fc022a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Code Signing External"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "9f1229cd8dd9092c27a01f5d56e3c0d59c2bb9f0139abf042e56f343637fda33"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 43 6F 64 65 20 53 69 67 6E 69 6E 67 20 45 78 74 65 72 6E 61 6C }
        $str1 = "semav6msr64.pdb"
        $str2 = "IOCTL_SEMAV6MSR64_CLEAR_ONE"
        $str3 = "IOCTL_SEMAV6MSR64_WRITE_ONE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_44575eec {
    meta:
        author = "Elastic Security"
        id = "44575eec-7fac-4544-8bb8-45b6bd82d6af"
        fingerprint = "afc52152b3c9a51ecb09a1737224c0faeef51d89ace31f44664e277d98d39fb3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: GE Intelligent Platforms Canada Company, Version: <= 9.50.0.7677"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "ae73dd357e5950face9c956570088f334d18464cd49f00c56420e3d6ff47e8dc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 45 20 49 6E 74 65 6C 6C 69 67 65 6E 74 20 50 6C 61 74 66 6F 72 6D 73 20 43 61 6E 61 64 61 20 43 6F 6D 70 61 6E 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 45 00 44 00 65 00 76 00 44 00 72 00 76 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x31][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x32-\x32][\x00-\x00][\x09-\x09][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1c]|[\x00-\xfc][\x1d-\x1d])[\x00-\x00][\x00-\x00]|[\x32-\x32][\x00-\x00][\x09-\x09][\x00-\x00][\xfd-\xfd][\x1d-\x1d][\x00-\x00][\x00-\x00])/
        $str1 = "GEDevDrv.pdb"
        $str2 = "Proficy Machine Edition" wide
        $str3 = "GE Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_52c8eb58 {
    meta:
        author = "Elastic Security"
        id = "52c8eb58-bc09-4a5b-b5b6-06a26d105028"
        fingerprint = "c938385a273c11d335aafa201d940bfdabebfcca5f6f66ad340afa4756c1b8ad"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation - Embedded Subsystems and IP Blocks Group"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "b78eb7f12ba718183313cf336655996756411b7dcc8648157aaa4c891ca9dbee"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E 20 2D 20 45 6D 62 65 64 64 65 64 20 53 75 62 73 79 73 74 65 6D 73 20 61 6E 64 20 49 50 20 42 6C 6F 63 6B 73 20 47 72 6F 75 70 }
        $str1 = "IoAccess.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Intel_1abb0887 {
    meta:
        author = "Elastic Security"
        id = "1abb0887-add0-48b3-ad69-8c2a98a3edea"
        fingerprint = "eeeebc2584661e208bbed65f0e036988cb4763ba6a1126e1b5a7948518bf062f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 6.5.1.31"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "b936c4ba80ccee3b0b3b67fc88c8caa103fcfc47888e976f6d5b6f113d22f41f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 4F 00 43 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x1e][\x00-\x00][\x01-\x01][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x1f-\x1f][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "iocbios2.pdb"
        $str2 = "Intel(R) Extreme Tuning Utility" wide
        $str3 = "Intel(R) Overclocking Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Intel_b78de5ce {
    meta:
        author = "Elastic Security"
        id = "b78de5ce-5f19-4905-a4bf-7e581590cb5b"
        fingerprint = "0f3130f232b5db48f11ffeb4957a64a984a4f053d783ab1a1c4a358b1537938e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Software Products"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "b96ba5c469591f9e545bef4af1719a831c73b71207fad79efd84335c1519f71a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 53 6F 66 74 77 61 72 65 20 50 72 6F 64 75 63 74 73 }
        $str1 = "sepdrv3_15.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Intel_c7f862f6 {
    meta:
        author = "Elastic Security"
        id = "c7f862f6-c438-4807-920f-5595f3b148bd"
        fingerprint = "f46ca7c95b49ada9fa228bcfd29f8de2159f6f7a2da687843e215d4edb63337f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel(R) Intel Network Drivers, Version: <= 1.3.1.0"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "f877296e8506e6a1acbdacdc5085b18c6842320a2775a329d286bac796f08d54"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 49 6E 74 65 6C 20 4E 65 74 77 6F 72 6B 20 44 72 69 76 65 72 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "iqvw64e.pdb"
        $str2 = "Intel(R) iQVW64.SYS" wide
        $str3 = "Intel(R) Network Adapter Diagnostic Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

