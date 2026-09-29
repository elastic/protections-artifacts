rule Windows_VulnDriver_Zntport_96b0c542 {
    meta:
        author = "Elastic Security"
        id = "96b0c542-0006-46dc-9144-2ba591289297"
        fingerprint = "c11de9103c400567cca106588745d118b36149cf8258e8c97f1976cba9b9d956"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: CLEVO CO., Version: <= 2.8.3.1"
        threat_name = "Windows.VulnDriver.Zntport"
        reference_sample = "c653fe66aeb6170899ad8b405b7550e247490a2366bda828bfa3b2a2dc18fa91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 4C 45 56 4F 20 43 4F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 7A 00 6E 00 74 00 70 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "zntport.pdb"
        $str2 = "NTPort Library" wide
        $str3 = "NTPort Library kernel driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

