rule Windows_VulnDriver_Paramount_a9c2d134 {
    meta:
        author = "Elastic Security"
        id = "a9c2d134-318a-46db-9b75-45f2dd011fe9"
        fingerprint = "3ac91bf0e50280e3df7629bf77159f8cfd1e30f5f1916752b42b307c0f135b9b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Paramount Software UK Ltd, Version: <= 6.1.1311.0"
        threat_name = "Windows.VulnDriver.Paramount"
        reference_sample = "02fa3060a8319f0f691547345863679d750bfea0974798ffcd379ee965bce83d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 61 6D 6F 75 6E 74 20 53 6F 66 74 77 61 72 65 20 55 4B 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 73 00 6D 00 6F 00 75 00 6E 00 74 00 65 00 72 00 65 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x04]|[\x00-\x1e][\x05-\x05])|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x1f-\x1f][\x05-\x05])/
        $str1 = "PSMounterEx.pdb"
        $str2 = "IOCTL_PSMOUNTER_QUERY_PERFORMANCE_DATA"
        $str3 = "IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE"
        $str4 = "\\DosDevices\\%c:"
        $str5 = "PSMounterEx" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Paramount_99ad27f2 {
    meta:
        author = "Elastic Security"
        id = "99ad27f2-596a-44de-8614-aae22db2d2b3"
        fingerprint = "2420d6b47ccc57b1c198353501840a3bd86887caeaec10559ec3101778db63cc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Paramount Software UK Ltd, Version: <= 7.2.4058.0"
        threat_name = "Windows.VulnDriver.Paramount"
        reference_sample = "4e99d454a56845bb0e622cfd68b895b7868ef7e8a43424e5b7b803f5a2d25eca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 61 6D 6F 75 6E 74 20 53 6F 66 74 77 61 72 65 20 55 4B 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 73 00 6D 00 6F 00 75 00 6E 00 74 00 65 00 72 00 65 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\xd9][\x0f-\x0f])|[\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00][\xda-\xda][\x0f-\x0f])/
        $str1 = "PSMounterEx.pdb"
        $str2 = "IOCTL_PSMOUNTER_QUERY_PERFORMANCE_DATA"
        $str3 = "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS"
        $str4 = "\\DosDevices\\%c:"
        $str5 = "PSMounterEx" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Paramount_b64d94cb {
    meta:
        author = "Elastic Security"
        id = "b64d94cb-fb6d-497d-816d-f3c9519e4436"
        fingerprint = "5b44b9b8d5bedafa0138238fee42b2ca088c48785537386f31a36d510aee18ab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Paramount Software UK Ltd"
        threat_name = "Windows.VulnDriver.Paramount"
        reference_sample = "e891526a0d3b9d8121657c55384e7c1a80ca96c9577cffb62681c700551ce0d6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 61 6D 6F 75 6E 74 20 53 6F 66 74 77 61 72 65 20 55 4B 20 4C 74 64 }
        $str1 = "psmounterex.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

