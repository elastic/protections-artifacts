rule Windows_VulnDriver_Inpout_fca58975 {
    meta:
        author = "Elastic Security"
        id = "fca58975-7375-4c1a-8036-42e597c074d2"
        fingerprint = "7aa9d2872d4868e92103187bf747bd210ed5cc2a2e9bdaf8507e92ad4939b2de"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: inpout32.sys, Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.Inpout"
        reference_sample = "16360ead229b13deb47bc2bef40f282474c9f18c213c636cdfb8cc2495168251"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 6E 00 70 00 6F 00 75 00 74 00 33 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "inpout32.pdb"
        $str2 = "inpout32 Driver Version 1.2" wide
        $str3 = "Kernel level port access driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Inpout_4bb85872 {
    meta:
        author = "Elastic Security"
        id = "4bb85872-4ce0-4b4e-9ae5-0fe676051183"
        fingerprint = "f81c2a4159b2c09fc2a678f5d79ec5f5c5b460feb3c0d8cfe0f861995115b2c6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: RISINTECH INC., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.Inpout"
        reference_sample = "2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 49 53 49 4E 54 45 43 48 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 6E 00 70 00 6F 00 75 00 74 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "inpoutx64.pdb"
        $str2 = "inpoutx64 Driver Version 1.2" wide
        $str3 = "Kernel level port access driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

