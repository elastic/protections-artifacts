rule Windows_VulnDriver_HP_931d8235 {
    meta:
        author = "Elastic Security"
        id = "931d8235-e098-4004-a949-9fb18e8d2708"
        fingerprint = "e1d5bac55a00a5a8f13440805831e20b500459f0e79ea23bb88b5829b894aa61"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HP Inc., Version: <= 20.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "0d383e469d0e27ebb713770f01f7f1a57068a7d30478221e6f2276125048d1c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 50 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 65 00 74 00 64 00 73 00 75 00 70 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "etdsupp.pdb"
        $str2 = "IOCTL_MG_SUPPORT_DRIVER_VERSION"
        $str3 = "HP ETDi Driver DLL" wide
        $str4 = "ETDi Support Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_HP_e7ac7f8c {
    meta:
        author = "Elastic Security"
        id = "e7ac7f8c-eddc-4802-bb08-94855941d9cf"
        fingerprint = "3c66fd618f59e05cd02f0b219725222775a49be831d6d4b69be577db71c8f445"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hewlett-Packard Company, Version: <= 4.5.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "4024b090cebcabaab884c84ec80ffb15622d12632f236383a9b0a470bff9fe33"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 65 77 6C 65 74 74 2D 50 61 63 6B 61 72 64 20 43 6F 6D 70 61 6E 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 71 00 73 00 79 00 73 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "cpqsysio64.pdb"
        $str2 = "Physical memory driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_HP_5c96add5 {
    meta:
        author = "Elastic Security"
        id = "5c96add5-b522-4d58-8f9d-027d1c4b8198"
        fingerprint = "3ce1434611c78dee61d5874f347375fecaa39090d25c9bf28aa3e91f43d393c8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HP Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "725d4445c65e1bf94c9fc8f07961512a8ad22628515bfa789b321a3169e0b65a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 50 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 53 00 50 00 4F 00 52 00 54 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SSPORT.pdb"
        $str2 = "Port Contention Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_HP_72cb1b4c {
    meta:
        author = "Elastic Security"
        id = "72cb1b4c-31a5-46fb-a5b6-8e860965e4bc"
        fingerprint = "336980c158973dfa4dbe99bb5827135a4686fce3c7fc96f064a13a112154365a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HP Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "a4680fabf606d6580893434e81c130ff7ec9467a15e6534692443465f264d3c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 50 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 70 00 50 00 6F 00 72 00 74 00 49 00 6F 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HpPortIO.pdb"
        $str2 = "HpPortIo" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_HP_a95d51ec {
    meta:
        author = "Elastic Security"
        id = "a95d51ec-57c7-426b-ae44-ef5339b55dc5"
        fingerprint = "590af546d46cb862eaa85dfe626fa9926948f4c4089bf7346dbdccbf248b11b6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hewlett-Packard Company, Version: <= 2.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "c1e11e2012216b54b2aad1be37b469d328f39b09352c66e8c74e6032ec858b96"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 65 77 6C 65 74 74 2D 50 61 63 6B 61 72 64 20 43 6F 6D 70 61 6E 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 70 00 36 00 34 00 76 00 69 00 73 00 69 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "hp64vision.pdb"
        $str2 = "HP Vision Hardware Diagnostics" wide
        $str3 = "hpvhd 64bit support driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

