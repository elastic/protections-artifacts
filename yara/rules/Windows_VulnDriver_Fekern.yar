rule Windows_VulnDriver_Fekern_7b7240f3 {
    meta:
        author = "Elastic Security"
        id = "7b7240f3-7e76-4b16-b5b8-34b5b1de31cc"
        fingerprint = "8ec69b50535e057f8a1bbfb9b2c3702d18ccfc426d2bf764956797a2ac39902b"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 34.8.0.0"
        threat_name = "Windows.VulnDriver.Fekern"
        reference_sample = "16f68c6e527aacd803cb2412766f00766527e1c880ed8da50bfedac501918320"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 66 00 65 00 6B 00 65 00 72 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x21][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x22-\x22][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x22-\x22][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "fekern.pdb"
        $str2 = "IOCTL_READ_PHYSICALMEMORY"
        $str3 = "IOCTL_COLLECTION_GETDATA"
        $str4 = "FireEye Realtime Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

