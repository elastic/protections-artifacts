rule Windows_VulnDriver_ASMMap_a0d6cf8d {
    meta:
        author = "Elastic Security"
        id = "a0d6cf8d-bf82-4c00-af3c-2b2a248316b4"
        fingerprint = "3e2b21c5e8afaeb8e422bb75782b8efabc24fdf77f5561bd19aeafa4a05657bf"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 1.0.9.1"
        threat_name = "Windows.VulnDriver.ASMMap"
        reference_sample = "025e7be9fcefd6a83f4471bba0c11f1c11bd5047047d26626da24ee9a419cdc4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 6D 00 6D 00 61 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "ASMMAP64.pdb"
        $str2 = "ATK Generic Function Service" wide
        $str3 = "Memory mapping Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_ASMMap_d0ea9c19 {
    meta:
        author = "Elastic Security"
        id = "d0ea9c19-0b80-4625-aaff-1db89ae240ec"
        fingerprint = "63daeca9cdb808b1d8ba19226b729f2b4c5bb9fad72353e5166fb493d7377d36"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 1.1.7.123"
        threat_name = "Windows.VulnDriver.ASMMap"
        reference_sample = "42baccea0fceb60b79f78098163147a8dd1ded24cb2f0dbb93edc07dab66135c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 6D 00 6D 00 61 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x7a][\x00-\x00][\x07-\x07][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x7b-\x7b][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "ASMMAP.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_ASMMap_30f56a96 {
    meta:
        author = "Elastic Security"
        id = "30f56a96-e907-4b96-a374-ee3c69a9d981"
        fingerprint = "1def89e0849d6c5b18798835a228fc33164030544c348b23cc6f0f7ea1d61334"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 1.1.7.123"
        threat_name = "Windows.VulnDriver.ASMMap"
        reference_sample = "5f76c140118b181427969237e364fd70b14fa36533061fd4d8eb2f4751706739"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 6D 00 6D 00 61 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x7a][\x00-\x00][\x07-\x07][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x7b-\x7b][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "ASMMAP64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

