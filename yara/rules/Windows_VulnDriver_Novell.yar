rule Windows_VulnDriver_Novell_faa58d6d {
    meta:
        author = "Elastic Security"
        id = "faa58d6d-cbf6-4ac8-9637-de96ba70dfc5"
        fingerprint = "8020b3b744f6dc3cfd6fbcda3059341ce7dc80d3660e186efb25d75c7a07950d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Novell, Inc., Version: <= 3.1.12.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "00b3ff11585c2527b9e1c140fd57cb70b18fd0b775ec87e9646603056622a1fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 76 65 6C 6C 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 49 00 43 00 4D 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00])/
        $str1 = "ncpl.pdb"
        $str2 = "XTCOM_Table"
        $str3 = "Novell XTier" wide
        $str4 = "Novell Client Portability Layer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Novell_399106e1 {
    meta:
        author = "Elastic Security"
        id = "399106e1-3800-4613-b087-b689ae0dd750"
        fingerprint = "0161c037a97f5d09a5331aa403d8714706f14e7e596eb920efd099dfdee0c534"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Publisher, Version: <= 3.1.11.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "2e665962c827ce0adbd29fe6bcf09bbb1d7a7022075d162ff9b65d0af9794ac0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 73 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "nscm.pdb"
        $str2 = "XTCOM_Table"
        $str3 = "Novell XTier" wide
        $str4 = "Novell XTier Session Manager" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Novell_214bc076 {
    meta:
        author = "Elastic Security"
        id = "214bc076-d025-4a3c-bc5d-e02bddd11344"
        fingerprint = "894319697677f3c24314387bfd2a6b48b8ae3c662b2f21df3ca6e9591bfbe131"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Novell, Inc., Version: <= 3.1.12.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "87e094214feb56a482cd8ae7ee7c7882b5a8dccce7947fdaa04a660fa19f41e5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 76 65 6C 6C 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6C 00 69 00 62 00 6E 00 69 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00])/
        $str1 = "nicm.pdb"
        $str2 = "IOCTL_REQUEST_REPLY"
        $str3 = "XTComDeregisterClassFactory"
        $str4 = "NicmDeregisterClassFactory"
        $str5 = "Novell XTier" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Novell_6e2f1747 {
    meta:
        author = "Elastic Security"
        id = "6e2f1747-c4a5-4c29-9b82-86c01ce479c1"
        fingerprint = "9b43e82d67e06e55bd36c8b4164970a1363a74c595d96a2edfe50b8eba2343b8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Publisher, Version: <= 3.1.11.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "e16dc51c51b2df88c474feb52ce884d152b3511094306a289623de69dedfdf48"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6C 00 69 00 62 00 6E 00 69 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "nicm.pdb"
        $str2 = "XTComDeregisterClassFactory"
        $str3 = "NicmDeregisterClassFactory"
        $str4 = "Novell XTier" wide
        $str5 = "Novell XTCOM Services Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Novell_b8fe37bf {
    meta:
        author = "Elastic Security"
        id = "b8fe37bf-e87c-49c3-9b45-521445111c31"
        fingerprint = "82787930465c0ad53e8379300e81de526976a0488454e9d5457d02b2a964f62f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Novell, Inc., Version: <= 3.1.11.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "f27febff1be9e89e48a9128e2121c7754d15f8a5b2e88c50102cecee5fe60229"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 76 65 6C 6C 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6C 00 69 00 62 00 6E 00 69 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "nicm.pdb"
        $str2 = "XTComDeregisterClassFactory"
        $str3 = "NicmDeregisterClassFactory"
        $str4 = "Novell XTier" wide
        $str5 = "Novell XTCOM Services Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Novell_6b3a456a {
    meta:
        author = "Elastic Security"
        id = "6b3a456a-adbc-4ba5-a020-6b99ba69e476"
        fingerprint = "9e7483b45ce225cb7332e06f1d333441a0c053ca7bbfa212f29df39e7a852dbc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Novell, Inc., Version: <= 3.1.12.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "f77fe6b1e0e913ac109335a8fa2ac4961d35cbbd50729936059aba8700690a9e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 76 65 6C 6C 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 73 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00])/
        $str1 = "nscm.pdb"
        $str2 = "XTCOM_Table"
        $str3 = "Novell XTier" wide
        $str4 = "Novell XTier Session Manager" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

