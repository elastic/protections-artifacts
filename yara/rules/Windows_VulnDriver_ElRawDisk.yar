rule Windows_VulnDriver_ElRawDisk_f9fd1a80 {
    meta:
        author = "Elastic Security"
        id = "f9fd1a80-048f-437f-badb-85d984af202d"
        fingerprint = "3d9dedd033cf07920eaa99b0d1fb654057def2bcef10080b45e1e8a285db8a4e"
        creation_date = "2022-10-07"
        last_modified = "2023-06-13"
        threat_name = "Windows.VulnDriver.ElRawDisk"
        reference_sample = "ed4f2b3db9a79535228af253959a0749b93291ad8b1058c7a41644b73035931b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\elrawdsk.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_ElRawDisk_c7b1e8d8 {
    meta:
        author = "Elastic Security"
        id = "c7b1e8d8-5c08-403b-a6c7-220d8b647951"
        fingerprint = "1003193fa1b6a68601a6b1a3b0e837d53d8e6947f11c9765cc58ec1d2fe2befb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EldoS Corporation, Version: <= 2.1.27.106"
        threat_name = "Windows.VulnDriver.ElRawDisk"
        reference_sample = "4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 64 6F 53 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 65 00 6C 00 72 00 61 00 77 00 64 00 73 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x1a][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x69][\x00-\x00][\x1b-\x1b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x6a-\x6a][\x00-\x00][\x1b-\x1b][\x00-\x00])/
        $str1 = "elrawdsk.pdb"
        $str2 = "RawDisk Driver. Allows write access to files and raw disk sectors for user mode applications in Windows 2000 and later." wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

