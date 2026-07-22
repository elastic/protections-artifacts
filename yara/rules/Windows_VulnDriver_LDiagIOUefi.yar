rule Windows_VulnDriver_LDiagIOUefi_bcd83f7a {
    meta:
        author = "Elastic Security"
        id = "bcd83f7a-421c-4e71-9cf8-eb51cfb35a70"
        fingerprint = "07aaee289f28331bb1b13791739e01a57a27e705495178c0d02bf6ccaf8da9f5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: LDiagIO_uefi.sys, Version: <= 3.1.0.4000"
        threat_name = "Windows.VulnDriver.LDiagIOUefi"
        reference_sample = "ef55a5a3be73d5bfc5aa2a2b3f0cc574b824d96a129a67931a1667e770d5d938"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 44 00 69 00 61 00 67 00 49 00 4F 00 5F 00 75 00 65 00 66 00 69 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x9f][\x0f-\x0f])[\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\xa0-\xa0][\x0f-\x0f][\x00-\x00][\x00-\x00])/
        $str1 = "ldiagio_uefi.pdb"
        $str2 = "LDiagIO for Windows Vista/2008 and later, installed on legacy or UEFI mode" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

