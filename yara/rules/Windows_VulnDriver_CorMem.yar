rule Windows_VulnDriver_CorMem_74b8606c {
    meta:
        author = "Elastic Security"
        id = "74b8606c-519e-4e05-9c8e-c92abf164cb9"
        fingerprint = "e8b72894d163035beb567bf0d26c4c9c7f7fc77bae8af9a902c27ed0a28ec9fa"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Teledyne Digital Imaging Inc., Version: <= 9.0.0.0"
        threat_name = "Windows.VulnDriver.CorMem"
        reference_sample = "40c855d20d497823716a08a443dc85846233226985ee653770bc3b245cf2ed0f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 6C 65 64 79 6E 65 20 44 69 67 69 74 61 6C 20 49 6D 61 67 69 6E 67 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 72 00 4D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Cormem.pdb"
        $str2 = "Sapera LT" wide
        $str3 = "Sapera Memory Manager" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

