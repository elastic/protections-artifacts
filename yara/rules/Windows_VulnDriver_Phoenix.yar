rule Windows_VulnDriver_Phoenix_af19f3c6 {
    meta:
        author = "Elastic Security"
        id = "af19f3c6-5b97-46a2-a418-3467eb2eab3b"
        fingerprint = "ab65c6680402ca87f4765e8beae8fd05148c8ff2384bdc3d596eae531bd8d2d1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Inc"
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "03920ed3f904838b65c2065a338f08ce062c40247539345ea8f4c158efe66634"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 49 6E 63 }
        $str1 = "TdkLib64Vs2015.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_77137808 {
    meta:
        author = "Elastic Security"
        id = "77137808-83f7-442b-80b3-58f73c3ef617"
        fingerprint = "6e183cb57b504e0643bf87437d421ca673be127ce533da61ee3084a517929dfb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "20d0759b3309603ea085ed31a636e42301df7ddcd358584e2ccd6cabf72af7c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLibVs2015.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_54a54fb1 {
    meta:
        author = "Elastic Security"
        id = "54a54fb1-9f1d-4a48-9984-fbf2e1966a3e"
        fingerprint = "b7be2a221fe995d36bd28c68a2570596b377e7f442be44d22ead7b306ec074c1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "2695390a8a7448390fe383beb1eee06d582202683f0273d6e72ef39a8cf709e1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLib64.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_ddac360a {
    meta:
        author = "Elastic Security"
        id = "ddac360a-bde6-4493-8d83-6e65adbec3d8"
        fingerprint = "a8c587561a85dd82da2367dee5a0b285398797d774adf309ac893abc630cd71f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technology Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "316a27e2bdb86222bc7c8af4e5472166b02aec7f3f526901ce939094e5861f6d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $str1 = "WinFlash64.pdb"
        $str2 = "\\Device\\WinFlash"
        $str3 = "\\DosDevices\\WinFlash"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_a39ae117 {
    meta:
        author = "Elastic Security"
        id = "a39ae117-3ca3-4e16-adf7-cc86a3381300"
        fingerprint = "8586bf3934a76d1395e1fcf19aa333a50ab43aa0d4e4407601817598ac1a8e38"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "39f137083e6c0200543e1f8d3c074f857d141bdb8c8f09338d48520537b881aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLib64Vs2015.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_9046c7fa {
    meta:
        author = "Elastic Security"
        id = "9046c7fa-d100-44f1-b229-6b5cdf96a65e"
        fingerprint = "7a46b350a0c754b63d80330772535a905f755add7b1fe6f5af5de5df15bac977"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd."
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "45a74b2e7ab35dc783375a4603efd961f6dfefaf3c134d453d6b76af94607e74"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $str1 = "TdkLib.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_00489dd4 {
    meta:
        author = "Elastic Security"
        id = "00489dd4-7669-4b27-8978-de87d3e700fc"
        fingerprint = "b0469617bb77ab0414f4be2ab118374c91db0d63cc1c922b429182258baaf59e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technology Ltd., Version: <= 1.6.0.1"
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 48 00 4C 00 41 00 53 00 48 00 4E 00 54 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "PhlashNT.pdb"
        $str2 = "WinPhlash" wide
        $str3 = "SWinFlash Driver for Windows NT" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_485e3cb7 {
    meta:
        author = "Elastic Security"
        id = "485e3cb7-b21f-44cc-a820-cb4f9a1b0d36"
        fingerprint = "ab9a01d2c89d7b73bbbf9b9643076e2cd03ac374a1d3cb61800aaec23928c388"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Ltd, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "6948480954137987a0be626c24cf594390960242cd75f094cd6aaa5c2e7a54fa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 67 00 65 00 6E 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Agent64.pdb"
        $str2 = "DriverAgent" wide
        $str3 = "DriverAgent Direct I/O for 64-bit Windows" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Phoenix_c655e0a4 {
    meta:
        author = "Elastic Security"
        id = "c655e0a4-f952-4074-8b70-8c7b9c0b473a"
        fingerprint = "1817d49c5625bc0d2d11327c2caa32f11cc75ec6ef750c8759d63c2ca378e05b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Phoenix Technologies Inc"
        threat_name = "Windows.VulnDriver.Phoenix"
        reference_sample = "7b2ed5b6f6296cdd3e61a915707355bd5325ce7f5a6fab43b7e1e550277ecaed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 49 6E 63 }
        $str1 = "TdkLib64.pdb"
        $str2 = "\\Device\\TdkLib"
        $str3 = "\\DosDevices\\TdkLib"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

