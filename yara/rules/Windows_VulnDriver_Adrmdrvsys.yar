rule Windows_VulnDriver_Adrmdrvsys_788229d1 {
    meta:
        author = "Elastic Security"
        id = "788229d1-8942-49d5-8410-d578cb112f4c"
        fingerprint = "192dcb41afadc665675463374d0656cdba84719c546ac54166c8a7bbc50bfb9c"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.12.802.2022"
        threat_name = "Windows.VulnDriver.Adrmdrvsys"
        reference_sample = "a1f79a2e1441970bb3e7c838f8c14a8f3d39a46b0ff9648614e922ac475c743d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 44 00 52 00 4D 00 44 00 52 00 56 00 53 00 59 00 53 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0b][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0c-\x0c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x21][\x03-\x03])|[\x0c-\x0c][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x22-\x22][\x03-\x03]|[\x0c-\x0c][\x00-\x00][\x01-\x01][\x00-\x00][\xe6-\xe6][\x07-\x07][\x22-\x22][\x03-\x03])/
        $str1 = "ADRMDRVSYS.pdb"
        $str2 = "ADLINK Resource Manager Kenerl Service." wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

