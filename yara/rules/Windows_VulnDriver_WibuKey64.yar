rule Windows_VulnDriver_WibuKey64_6cfaa7de {
    meta:
        author = "Elastic Security"
        id = "6cfaa7de-4365-4a89-b0b5-9ebdb73efd9c"
        fingerprint = "df1a379aa2edc6b6020fdf6a414fdb8dd1c5145ffb6ce51de9cc335d051ad99f"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: WIBU-SYSTEMS AG, Version: <= 6.50.3314.501"
        threat_name = "Windows.VulnDriver.WibuKey64"
        reference_sample = "7ab52ce255f4ee1d192e9a3cc0b836eaea10bd3c2d0d732519eb2f5968617ffd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 49 42 55 2D 53 59 53 54 45 4D 53 20 41 47 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 62 00 75 00 4B 00 65 00 79 00 36 00 34 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x31][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x32-\x32][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0b]|[\x00-\xf1][\x0c-\x0c])|[\x32-\x32][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xf4][\x01-\x01])[\xf2-\xf2][\x0c-\x0c]|[\x32-\x32][\x00-\x00][\x06-\x06][\x00-\x00][\xf5-\xf5][\x01-\x01][\xf2-\xf2][\x0c-\x0c])/
        $str1 = "WibuKey64.pdb"
        $str2 = "WibuKey Software Protection System" wide
        $str3 = "WibuKey Windows NT Kernel Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

