rule Windows_Rootkit_Generic_5b1586ea {
    meta:
        author = "Elastic Security"
        id = "5b1586ea-be99-4f4d-9546-9bda43748fe1"
        fingerprint = "226f51f3a5280b428c5341802c9c35c884809e0a950c3ed65fa5b99ceb6a14ab"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: Beijing JoinHope Image Technology Ltd., Version: <= 2022.10.11.926"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "24c900024d213549502301c366d18c318887630f04c96bf0a3d6ba74e0df164f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4A 6F 69 6E 48 6F 70 65 20 49 6D 61 67 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x9d][\x03-\x03])[\x0b-\x0b][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07][\x9e-\x9e][\x03-\x03][\x0b-\x0b][\x00-\x00])/
        $str1 = "FilDriverx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

rule Windows_Rootkit_Generic_e94ca533 {
    meta:
        author = "Elastic Security"
        id = "e94ca533-1e27-44a6-b8ff-092d47a168db"
        fingerprint = "df111196f95a01031f22cbefa3bde2d6d89f5c99ec31e53d8513e875415a6be3"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: 湖南蓝途方鼎科技有限公司"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "7a84703552ae032a0d1699a081e422ed6c958bbe56d5b41839c8bfa6395bee1d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 B9 96 E5 8D 97 E8 93 9D E9 80 94 E6 96 B9 E9 BC 8E E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "RedDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_aa10c0ad {
    meta:
        author = "Elastic Security"
        id = "aa10c0ad-de61-4a47-bdbe-f232e4e383e2"
        fingerprint = "e8da953d36cd407c1e56e89f50609f2a66c507d5900a1205ce6f25c7be1345ce"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: Zhuhai liancheng Technology Co., Ltd."
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "0440ef40c46fdd2b5d86e7feef8577a8591de862cfd7928cdbcc8f47b8fa3ffc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 68 75 68 61 69 20 6C 69 61 6E 63 68 65 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "KApcHelper.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_dc7b1255 {
    meta:
        author = "Elastic Security"
        id = "dc7b1255-513d-4e8a-9dd1-1903a931d32a"
        fingerprint = "acf2f2b7ed2fbc2be6152cf5476253db65cb821ceeef209d1dcfc01c7a0ecf0e"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: Beijing Founder Apabi Technology Limited"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "df72cb33a23ae8f6f9dc64bb738fcfaea959368ce05cf399f3c7db5e90104bd7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 46 6F 75 6E 64 65 72 20 41 70 61 62 69 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 69 6D 69 74 65 64 }
        $str1 = "MDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_6a1fb6e5 {
    meta:
        author = "Elastic Security"
        id = "6a1fb6e5-dcfa-4b83-9e43-aeb2f82076cd"
        fingerprint = "d01e5958846990428a8f8dfd15fcc6a53c978be74b3dc208d121b948fe5dd4b9"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: 重庆貔赑貅软件科技工作室 (王真)"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "f154167b4b92851f478b3c3f88423cd719e3139bac5da07f33dd7929796c96f5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 87 8D E5 BA 86 E8 B2 94 E8 B5 91 E8 B2 85 E8 BD AF E4 BB B6 E7 A7 91 E6 8A 80 E5 B7 A5 E4 BD 9C E5 AE A4 20 28 E7 8E 8B E7 9C 9F 29 }
        $str1 = "project-ioctl.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_06e4d47e {
    meta:
        author = "Elastic Security"
        id = "06e4d47e-8db9-4e95-9fea-b13e9666c646"
        fingerprint = "6efa09308a4142a11b89e243258cd9192768e7c030b64cb4fad797ff4861c1ea"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: WDKTestCert anash,133231280654008727"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "0ae8d1dd56a8a000ced74a627052933d2e9bff31d251de185b3c0c5fc94a44db"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 61 6E 61 73 68 2C 31 33 33 32 33 31 32 38 30 36 35 34 30 30 38 37 32 37 }
        $str1 = "Chaos-Rootkit.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_d141ff75 {
    meta:
        author = "Elastic Security"
        id = "d141ff75-6ffe-4cae-b839-cdbbfe74bfe4"
        fingerprint = "283e528a24c138af82ea527a8dd8c132aa2ef340d84e316adb482b224297cd30"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: WDKTestCert zezec,132961360795713868"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "23e89fd30a1c7db37f3ea81b779ce9acf8a4294397cbb54cff350d54afcfd931"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 7A 65 7A 65 63 2C 31 33 32 39 36 31 33 36 30 37 39 35 37 31 33 38 36 38 }
        $str1 = "Malicious.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_3dd0612c {
    meta:
        author = "Elastic Security"
        id = "3dd0612c-3ff5-4c49-8afb-a8c4eef340fa"
        fingerprint = "7f803fced1328034faa11c2dd038f8bc1312c1f8d8321a66df2d75fc68655081"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "70c9f9e8dcbba700e0fc20e6ae9b4c5df98326cf212ac8794fc8ee9a46e948c4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "Bro:[%S] Remot:[%s:%d] loP:[%d]->[%d]"
        $str2 = "Add SignSize:%d SignCrc32:%x SignSize2:%d IsSearchFullFile:%d TimeDateStamp:%d"
        $seq1 = { 48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 8B F9 32 DB 48 8D 0D C6 77 00 00 E8 8D 31 00 00 48 8B 05 2A 78 00 00 48 8D 2D 23 78 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $seq1
}

rule Windows_Rootkit_Generic_27a16313 {
    meta:
        author = "Elastic Security"
        id = "27a16313-d6d5-4c51-bdff-e693f794ecc2"
        fingerprint = "92783cb21c84ba4aaef32d6fc3735a197771f76d2131907f9a28b0916e5d1cea"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "ee8844ffd3879190fb389b0f613cb2dcdcd83375cf0a6994170a648c5ca8c479"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 33 C0 48 89 44 24 20 66 89 44 24 28 0F 01 4C 24 20 48 8B 4C 24 22 48 85 C9 0F 84 D4 00 00 00 8B FE 49 BE 00 00 00 00 00 F0 FF FF 0F 1F 84 00 00 00 00 00 }
        $seq2 = { BA C0 AB 8E F3 48 8B CB E8 B7 F6 FF FF }
        $str1 = "\\Device\\devhost" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $seq1 and $seq2 and $str1
}

rule Windows_Rootkit_Generic_6d746554 {
    meta:
        author = "Elastic Security"
        id = "6d746554-db20-41cd-9480-81d245859eca"
        fingerprint = "0a63d8b23efbbd8ceee2c8acb90c7f7b456bd6d17d04e7331c522eeb5262f19c"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "4f412f9aa89994cda45422d23d6d961809225de9a4f5a8bfbfb9ac0e8725917e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "F:\\Source Codes\\IceCubes-Driver\\x64\\Release\\Windows-Ice-Monitor.pdb"
        $seq1 = { B8 4F EC C4 4E 41 F7 E0 C1 EA 05 0F B7 C2 6B C8 68 41 0F B7 C0 41 FF C0 66 2B C1 66 83 C0 62 66 41 31 01 4D 8D 49 02 41 83 F8 17 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}

rule Windows_Rootkit_Generic_740b1440 {
    meta:
        author = "Elastic Security"
        id = "740b1440-b4bd-4f7f-bdf0-a06fd85ddc5f"
        fingerprint = "494f1f6e4920b78e21aff2db98f400388f74724c76ec5d44ebdce169ba378a6a"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "4473fef2a90a3217db685de44f575d2586666fcf3db7fa9efa1328afcdbf34a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DosDevices\\isj2uaoX" wide
        $str2 = "C:\\Intel\\x"
        $seq1 = { 48 8D 50 30 48 F7 D8 48 1B C0 48 23 C2 48 3B 47 08 75 06 8B 47 10 89 43 08 48 8B 5C 24 30 32 C0 48 83 C4 20 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1 and $str2 and $seq1
}

rule Windows_Rootkit_Generic_7957ff72 {
    meta:
        author = "Elastic Security"
        id = "7957ff72-2aa8-4327-90c0-5674a0dcd5bc"
        fingerprint = "ff6131469e2be71d9a88e05584a6c51432836beaa2fbdb080b94bf2c4d426917"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "42bbad0caff790db44833fc67a202850576d73d278ea85fb8095e3f93b0b4370"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "D:\\Projects\\StolenDriver\\KMDF\\bin\\Release\\watabe.pdb"
        $str2 = "\\DosDevices\\safezone04" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

rule Windows_Rootkit_Generic_53c58b40 {
    meta:
        author = "Elastic Security"
        id = "53c58b40-b1bf-4db7-bd80-4d6f86dd06a1"
        fingerprint = "7c12b3c93ffb4bb7e4173e77e1c716aa91914377befcf403960b63fbb95ca911"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "412564937dea61ad443a3f50a0f7586aed1bf68795e9af184606804357499cea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "D:\\projects\\memdrv\\build\\x64\\Release\\memdrv.pdb"
        $str2 = "\\Device\\Redirt" wide
        $seq1 = { 41 8B C0 2D 0C A0 22 00 74 61 83 E8 04 74 55 83 E8 14 74 49 2D DC 3F 00 00 74 25 83 F8 20 74 16 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $seq1
}

rule Windows_Rootkit_Generic_a721bb54 {
    meta:
        author = "Elastic Security"
        id = "a721bb54-88fd-4108-bb44-b66faae40b57"
        fingerprint = "18294e2ffe04889ce0e96750405ca39b30267e32cb3001246e1db1c51ecec136"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "c3ea9a13da6f137238b4b912b1f398b8ccfae41ba618993e6cc6c73eb24800db"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "F:\\Source Codes\\Aspect-Driver-Rewrite\\x64\\Release\\Windows-Memory-Informer.pdb"
        $str2 = "\\Driver\\MouClass" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

rule Windows_Rootkit_Generic_d64a5561 {
    meta:
        author = "Elastic Security"
        id = "d64a5561-7f00-4ee5-9f9b-3913bcee6dbd"
        fingerprint = "ed0cb8fd06ca3b084737f0ada26c9949f40b75b721d7f7d193a8436ecf8d8e4f"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: WDKTestCert youss,133730752550224793"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "7ccb02b9dc8bb46e5ea32fb8f4c93bac195bcbb0c2fc02d3af28f4208afe7c41"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 79 6F 75 73 73 2C 31 33 33 37 33 30 37 35 32 35 35 30 32 32 34 37 39 33 }
        $str1 = "D:\\Games\\YoussiLovesPenis\\Kinkajou\\x64\\Release\\Kinkajou.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_e4cb3338 {
    meta:
        author = "Elastic Security"
        id = "e4cb3338-7780-45bd-b46c-1a52c325f887"
        fingerprint = "243b30e3142328c210261825b89b4f8fdc5d7cd14709cde7103e6eee2bd845ac"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "1da4f7f001d239a54fab50eb7c3cbc985db392a3d4405e19c3a5d2035d591004"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "\\DosDevices\\%x" wide
        $seq1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 05 87 22 00 00 48 8D 1D 78 22 00 00 48 8B F9 48 8D 0D 5E 22 00 00 48 3B C1 74 45 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}

rule Windows_Rootkit_Generic_16e8136e {
    meta:
        author = "Elastic Security"
        id = "16e8136e-482e-49b2-b7b5-a9952b570abe"
        fingerprint = "c1ed4b86934e6658253cdf7c9b6c83dfcfd4ce0ce8e0f8b76889a5b9db6f9222"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 0.0.243.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "e9a1c39600193c7fd546733284a575b2d5192e2fd3ff64ca1a33b00739f8d429"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xf2][\x00-\x00]|[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\xf3-\xf3][\x00-\x00])/
        $str1 = "intigua_driver64.pdb"
        $str2 = "Intigua Release Linux32" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_Rootkit_Generic_1ca756ee {
    meta:
        author = "Elastic Security"
        id = "1ca756ee-e9f8-405e-8a39-3b4caed4347b"
        fingerprint = "63bdd69245d668a9d4682afd21418049bfc16a35c711bfa85a89529107bcfdba"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: WDKTestCert yo,133912822835426319"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "f5dd6db447868c2964c1d109e7d2cc31ebdace198b3d0a02cfba5b7ef7ae6964"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 79 6F 2C 31 33 33 39 31 32 38 32 32 38 33 35 34 32 36 33 31 39 }
        $str1 = "C:\\Users\\Public\\wtf.pdb"
        $str2 = "\\DosDevices\\Kinkajou" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

rule Windows_Rootkit_Generic_e59bd290 {
    meta:
        author = "Elastic Security"
        id = "e59bd290-2bda-4bfc-a1ff-67c612185f24"
        fingerprint = "30d22ceba3031dea1af6118920ecfbd3c286422bb612014b03063237d0478f50"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "d6d219628ab3acdc799b1b631d378742a4b266d6f55b12e568e4054091b08be6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "C:\\Users\\Blluettw -_-\\Downloads\\ioctl-main\\kprlRW\\x64\\Release\\kprl.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_1a5e47b6 {
    meta:
        author = "Elastic Security"
        id = "1a5e47b6-c297-4c52-8cd4-66b64afe29cd"
        fingerprint = "fd0ec05cf03de2e1fe2305781cf926af57ec72264a1d4f93194bf9113248cc95"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "e8b1a0ddc7a4404eb3c46217e07b5ed91723f44464a6ef589634aeb4fb8f5666"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $seq1 = { 53 56 57 BB 55 55 00 00 33 FF EB 5E 33 F6 66 8B 31 0F B7 C6 C1 E8 06 83 F8 01 8D 1C 9F 7C 58 83 F8 03 7F 53 8B D6 33 D3 2B D7 2A D0 83 E2 3F 8B C2 33 D2 66 3D 0A 00 73 05 8D 50 30 EB 09 }
        $seq2 = { F6 C3 01 74 02 33 D1 8B C1 C1 E8 1F D1 E1 85 C0 74 06 81 F1 E9 35 79 35 }
        $seq3 = { 3B CB 74 52 81 F9 84 20 01 AA 74 4A 81 F9 88 20 01 AA 74 36 81 F9 C0 20 01 AA 74 25 81 F9 C4 20 01 AA 75 09 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $seq1 and $seq2 and $seq3
}

rule Windows_Rootkit_Generic_6eff9444 {
    meta:
        author = "Elastic Security"
        id = "6eff9444-3faf-4373-9e92-289702b5dd50"
        fingerprint = "70d05bcdc6e1e77af98f8cbd67565aaf298eb2803b7d27a7d4678dd62337ae22"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Fuzhou Dingxin Trade Co., Ltd."
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "927e3aef03a8355d236230cace376b3023480a40c5ac08453c07dab343dd1f11"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 75 7A 68 6F 75 20 44 69 6E 67 78 69 6E 20 54 72 61 64 65 20 43 6F 2E 2C 20 4C 74 64 2E }
        $seq1 = { 82 54 FB 7A BF 7D 81 AB 93 BD 7D E2 9A E4 13 43 82 46 1E 2F E8 8A }
        $seq2 = { 3B B3 60 B9 26 82 1A 76 B4 70 3E AF 67 7D B7 5C 4E 11 6E D1 B6 65 7C 2C 8C 8E 57 C9 07 60 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1 and $seq2
}

rule Windows_Rootkit_Generic_37cc75c1 {
    meta:
        author = "Elastic Security"
        id = "37cc75c1-fa15-4009-821d-ba5ab493f61a"
        fingerprint = "12869f993b9a65b5e32b954db873738afa7b4b0aba3a87a178e78b92c7a66a39"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: FEI XIAO, Version: <= 1.0.0.1"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "c619a7fbb27940428b80129e0fa2d976fce52f93ab37667d2ca01330c6c561a5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 45 49 20 58 49 41 4F }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HalMakeBeep"
        $seq1 = { 51 F6 D6 F8 66 D3 C2 53 48 31 E3 48 0F B3 C3 48 89 C3 C0 DE 03 D2 C2 66 0F BB E2 F5 BA 01 00 00 00 48 0F BA E0 21 83 F9 07 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $seq1
}

rule Windows_Rootkit_Generic_362cd75f {
    meta:
        author = "Elastic Security"
        id = "362cd75f-519a-442e-a9af-5017b33449a8"
        fingerprint = "9dc485bb7f0630fdfe352e0d2a5da23f8ea9e51ad887a9ff616c40c66e85db3b"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: 长沙恒祥信息技术有限公司"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "d51d00127ddd4551fb1eafe14255715014944ad4c60eabb9e568c3ff98ff4a2e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 95 BF E6 B2 99 E6 81 92 E7 A5 A5 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $seq1 = { 41 54 48 C7 44 24 08 EB 0A B7 70 48 8D 64 24 08 E8 F9 3A 14 00 E8 33 73 B8 FF C9 EC }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1
}

rule Windows_Rootkit_Generic_2881653d {
    meta:
        author = "Elastic Security"
        id = "2881653d-600f-48d3-be76-cae9f911d8b9"
        fingerprint = "d186030d0d42619efd9fda9a1b22ad2d26f1de8e724337a1b62419beb51732cd"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "ede9a3858a12d5ddea21a310e5721bf86c2248539f42c9e0c3c29ae5b0148ba5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "e:\\repos\\pcm\\winmsrdriver\\win7\\objfre_win7_amd64\\amd64\\msr.pdb"
        $seq1 = { 48 89 5C 24 08 48 89 74 24 18 57 48 83 EC 60 48 8B 05 76 E0 FF FF 48 33 C4 48 89 44 24 58 48 8B 8A B8 00 00 00 33 DB 48 8B FA 48 3B CB 0F 84 DD 01 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}

rule Windows_Rootkit_Generic_5b621593 {
    meta:
        author = "Elastic Security"
        id = "5b621593-ca91-4e58-b8ae-e9a52af633b0"
        fingerprint = "7554cca0506548c001b7e437b6de2125062ac6d0eb9660704b7006a454f57b88"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "274340f7185a0cc047d82ecfb2cce5bd18764ee558b5227894565c2f9fe9f6ab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $seq1 = { 41 BC 01 00 00 00 40 D2 F7 BA 01 00 00 00 40 32 FF F9 0F AC ED A1 BF 01 00 00 00 48 0F AC F5 30 41 D2 C6 45 3A D9 45 32 DB 66 41 0F C1 EE 66 3B FA 41 0F A4 DA 8F D3 E2 8B 48 04 41 81 CE 9A 07 D8 47 }
        $seq2 = { 0F C8 F8 66 F7 C5 D4 0A 40 84 DF 55 40 D2 CD 40 0F 9B C5 31 04 24 66 44 0F A3 F5 41 2A E8 5D 41 F6 C1 BD 48 63 C0 4C 03 D0 41 FF E2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1 and $seq2
}

rule Windows_Rootkit_Generic_7f6750a0 {
    meta:
        author = "Elastic Security"
        id = "7f6750a0-4bc9-4707-9c8b-6b25b452a34a"
        fingerprint = "b6c2c84f7479ab17fc6766456a370fc5a50dcfc5970d4e902e445ec3c8779be8"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "6165491e8391eac9c0e3b9a2a31e1692a567c16cbfa36d7a88c401ffae1f6c63"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq1 = { 48 57 48 83 EC 40 4C 8B C1 48 8D 0C 24 48 2B CA 0F B7 02 66 89 04 11 48 83 C2 02 66 85 C0 75 F0 33 FF 48 8D 14 24 66 41 B9 55 55 66 39 3C 24 74 72 0F B7 0A 66 41 C1 E1 02 44 8B D1 66 44 03 CF 41 C1 EA 06 41 8D 42 FF 83 F8 02 77 56 41 32 C9 66 33 C0 40 2A CF 41 2A CA 66 83 E1 3F 66 83 F9 0A 73 05 8D 41 30 EB 09 }
        $seq2 = { 41 0F B7 04 00 66 43 89 04 18 49 83 C0 02 66 85 C0 75 E6 }
        $seq3 = { 41 BB 44 20 01 AA 8B C1 8B F1 41 3B D3 41 BA 44 30 01 AA 74 0F 41 3B D2 75 11 B8 08 00 00 00 8D 70 FC EB 07 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $seq1 and $seq2 and $seq3
}

rule Windows_Rootkit_Generic_c819f0a8 {
    meta:
        author = "Elastic Security"
        id = "c819f0a8-b8a4-40f4-9dae-2793387f3d41"
        fingerprint = "4c45366cd892f0dbbd3457f510531539aa3f779e2d168aca3276ac4cbffecd69"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: 1.A Connect GmbH, Version: <= 1.0.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "6709a2d7925248fe172e9bc5495f45b9bb74060c43e1c58e671f0e6c434fd82b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 31 2E 41 20 43 6F 6E 6E 65 63 74 20 47 6D 62 48 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 0F 9D C1 49 8D 4E 08 4C 8B C0 F6 D0 66 99 4C 8D 4C 24 20 49 8B 06 48 63 D5 49 0F BF D7 48 89 47 10 48 0F CA 89 5F 08 49 0F B7 D7 49 0F 44 D3 66 40 0F B6 D5 0F 10 07 41 0F 40 D2 0F B7 D3 41 0F BF D6 8B 16 0F 10 4F 10 0F 29 44 24 20 F2 0F 10 47 20 F2 0F 11 44 24 40 E9 00 00 00 00 }
        $seq2 = { 41 B8 FD FF FF FF C7 45 B8 FC FF FF FF 83 C9 FF C6 45 BC D1 44 89 45 C0 48 8B FB C6 45 C4 48 41 8D 50 01 C6 45 CC 8B 8D 42 FD 89 55 C8 89 45 98 89 44 24 78 89 44 24 38 89 44 24 58 8B 05 00 4D 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}

rule Windows_Rootkit_Generic_c175b7cc {
    meta:
        author = "Elastic Security"
        id = "c175b7cc-336e-4672-9ed8-042fa06c315e"
        fingerprint = "f1dd833336500bc1aaabf32795539ae409a9b4464021b647992098640959625f"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: 12980215 Canada Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "f6d7faddc3a56875a8d24e4785a139141dd892968f70bf0e37d505af9a3324fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 31 32 39 38 30 32 31 35 20 43 61 6E 61 64 61 20 49 6E 63 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 4C 8B C0 49 D3 F1 66 C1 C1 76 49 89 06 48 F7 D8 66 98 0F 31 4D 0F BF CD 48 C1 E2 20 E9 00 00 00 00 4C 8B CF C6 C5 64 48 0B C2 49 8B CF 49 89 00 8B D5 40 80 FD 4A F9 49 83 C0 08 89 5F 08 E9 00 00 00 00 }
        $seq2 = { 68 B4 F6 E3 D5 E8 00 CF F7 FF 6E 68 44 30 70 6E E8 42 7E F3 FF 6A 68 BC 42 FB D5 E8 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}

rule Windows_Rootkit_Generic_b1ca6fd0 {
    meta:
        author = "Elastic Security"
        id = "b1ca6fd0-3651-4ec0-a1b0-c54642d05166"
        fingerprint = "a34bb722a914ab1646535f4de55c81b94e5906e3145b693bff139bce386c5cc4"
        creation_date = "2026-07-25"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "c1c4310e5d467d24e864177bdbfc57cb5d29aac697481bfa9c11ddbeebfd4cc8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "Z:\\NewProjects\\hide_tools\\objfre\\i386\\hidetools.pdb"
        $str2 = "\\registry\\machine\\system\\CurrentControlSet\\Enum\\Root\\LEGACY_%ws" wide
        $seq1 = { 8B 46 04 43 83 E8 08 43 FF 45 08 D1 E8 39 45 08 72 C7 03 76 04 EB A1 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and $str2 and $seq1
}

rule Windows_Rootkit_Generic_d5aa37d2 {
    meta:
        author = "Elastic Security"
        id = "d5aa37d2-f332-4709-a00a-1eb7fdd24b81"
        fingerprint = "df63d903f08d1fb137ecd817403a0a16b4d0f35e05dd497d8009c2b746dd9f98"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Shenzhen Intech Indesign Technology Co., Ltd, Version: <= 3.0.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "d312788921ec8e92f9ccc606b51b7d940933c6bda812d293d3f713c6225305f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 49 6E 74 65 63 68 20 49 6E 64 65 73 69 67 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_Rootkit_Generic_fbced6b4 {
    meta:
        author = "Elastic Security"
        id = "fbced6b4-b858-4f9e-90c2-a244e08bbe74"
        fingerprint = "e88bc5ec4c2927be7d150762e71de8861870f240bd948fe1484165c27aed1214"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: Hunan Goldmind Education Equipment Co., Ltd., Version: <= 3.0.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "06cc1ce9a1d413b2ba156adcb8e9d398cba4027de1b7b98e1c2fe49e54193c70"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 6E 61 6E 20 47 6F 6C 64 6D 69 6E 64 20 45 64 75 63 61 74 69 6F 6E 20 45 71 75 69 70 6D 65 6E 74 20 43 6F 2E 2C 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_Rootkit_Generic_21251bf7 {
    meta:
        author = "Elastic Security"
        id = "21251bf7-51ae-4c98-ab1e-17c1179c0e1f"
        fingerprint = "b055b3287deea2094e14bca15acf206c23406f8423915a5abcac3a3dc215e735"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "f461414a2596555cece5cfee65a3c22648db0082ca211f6238af8230e41b3212"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "INT-Base10.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_8b068737 {
    meta:
        author = "Elastic Security"
        id = "8b068737-3019-481e-8147-bb871952451d"
        fingerprint = "d6c444fd496e3eee38c8fc5ddeda0d677eeceda82be4dfba396ba1f113217c8e"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.6.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "7f4555a940ce1156c9bcea9a2a0b801f9a5e44ec9400b61b14a7b1a6404ffdf6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Sense5 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

rule Windows_Rootkit_Generic_74a58b37 {
    meta:
        author = "Elastic Security"
        id = "74a58b37-0f09-48a3-9cff-91f8fdccd20d"
        fingerprint = "418e128b26ed6021c757e9eac380a684d6a9908a7f3b74c2983028e9348e9fba"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: 中兴通讯股份有限公司"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "1c763af41b74c7502d70093763723939a8025199e0ac7e39c04b5cf992f9e273"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B8 AD E5 85 B4 E9 80 9A E8 AE AF E8 82 A1 E4 BB BD E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "rwdriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_Rootkit_Generic_fd0021b8 {
    meta:
        author = "Elastic Security"
        id = "fd0021b8-be8b-4b80-b501-c2b82398c149"
        fingerprint = "7e6db4cb65925c0db3e2b66e6bb056ffeefe90e2ca52e73e5eead194d56675f1"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.5.0.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "42b22faa489b5de936db33f12184f6233198bdf851a18264d31210207827ba25"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Sense5 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

rule Windows_Rootkit_Generic_23507a9c {
    meta:
        author = "Elastic Security"
        id = "23507a9c-7001-4888-befe-cc3556138b98"
        fingerprint = "89d66fdbfc41c9f7bb87243056b642f20e5f0a71d8b54885dd12942e2acf6865"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "575e58b62afab094c20c296604dc3b7dd2e1a50f5978d8ee24b7dca028e97316"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "\\code\\[2-5]fileopr\\objfre_win7_amd64\\amd64\\MyDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

