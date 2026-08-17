rule Windows_VulnDriver_Adlice_c52f122c {
    meta:
        author = "Elastic Security"
        id = "c52f122c-58a7-4cdc-9b80-c7f7ef374293"
        fingerprint = "071adac8ad31e6f07adaf3ad3b25ecf2e1de3baf9283ee6767cf42bb81afe40f"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 3.4.1.0"
        threat_name = "Windows.VulnDriver.Adlice"
        reference_sample = "85b69f4e518c66b8ba7154ecb1ac1e8791dfe2fdf1e20b7c3a707f59639ac10d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 64 00 6C 00 69 00 63 00 65 00 20 00 52 00 6F 00 6F 00 74 00 4C 00 61 00 73 00 65 00 72 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "truesight.pdb"
        $str2 = "Adlice RootLaser" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

