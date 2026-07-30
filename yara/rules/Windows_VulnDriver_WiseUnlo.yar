rule Windows_VulnDriver_WiseUnlo_eb95ce82 {
    meta:
        author = "Elastic Security"
        id = "eb95ce82-9f89-480d-8dec-9795e94d48ca"
        fingerprint = "ef707b1a72de820d766d8632ce31bde2b4d7a5810a524656c89cc5404e7bef40"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Lespeed Technology Ltd., Version: <= 1.0.1.12"
        threat_name = "Windows.VulnDriver.WiseUnlo"
        reference_sample = "5e27fe26110d2b9f6c2bad407d3d0611356576b531564f75ff96f9f72d5fcae4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 73 70 65 65 64 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 73 00 65 00 55 00 6E 00 6C 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0b][\x00-\x00][\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x0c-\x0c][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "WiseUnlock.pdb"
        $str2 = "WiseUnlo" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_WiseUnlo_0aa0f0de {
    meta:
        author = "Elastic Security"
        id = "0aa0f0de-c081-4969-8460-81b0ce827e09"
        fingerprint = "225fd14bdddd3f2bba2f51a0e2e49f61ff1cd7b14055205944094b447b95189c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Lespeed Technology Co., Ltd, Version: <= 1.0.2.13"
        threat_name = "Windows.VulnDriver.WiseUnlo"
        reference_sample = "786f0ba14567a7e19192645ad4e40bee6df259abf2fbdfda35b6a38f8493d6cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 73 70 65 65 64 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 73 00 65 00 55 00 6E 00 6C 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0c][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x0d-\x0d][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "WiseUnlock.pdb"
        $str2 = "WiseUnlo" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_WiseUnlo_76db4cea {
    meta:
        author = "Elastic Security"
        id = "76db4cea-d595-41e5-9639-0123532f4fa8"
        fingerprint = "d5f5432aa730401a94d650e7e69a93a464fa0b367042bd65dfbf96a1fd72be0e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing Lang Xingda Network Technology Co., Ltd, Version: <= 1.0.2.13"
        threat_name = "Windows.VulnDriver.WiseUnlo"
        reference_sample = "87aae726bf7104aac8c8f566ea98f2b51a2bfb6097b6fc8aa1f70adeb4681e1b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4C 61 6E 67 20 58 69 6E 67 64 61 20 4E 65 74 77 6F 72 6B 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 73 00 65 00 55 00 6E 00 6C 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0c][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x0d-\x0d][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "WiseUnlock.pdb"
        $str2 = "WiseUnlo" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

