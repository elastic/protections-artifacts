rule Windows_VulnDriver_Sioctl_00f9317d {
    meta:
        author = "Elastic Security"
        id = "00f9317d-c9f6-417b-a349-7414792b4b4e"
        fingerprint = "1b74060bf2f0528a54d9f74a970a23bda029a73ed24facc101608977245675ae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WDKTestCert Neil,131715585907434400, Version: <= 10.0.10011.16384"
        threat_name = "Windows.VulnDriver.Sioctl"
        reference_sample = "3a24b63cce5a4b7bd6188940af75b05a414b283c3c8eb528b5ba607ef720fc93"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 4E 65 69 6C 2C 31 33 31 37 31 35 35 38 35 39 30 37 34 33 34 34 30 30 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 49 00 4F 00 43 00 54 00 4C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x26]|[\x00-\x1a][\x27-\x27])|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3e]|[\x00-\xff][\x3f-\x3f])[\x1b-\x1b][\x27-\x27]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x40-\x40][\x1b-\x1b][\x27-\x27])/
        $str1 = "PhyMEMCtrl.pdb"
        $str2 = "IOCTL_SIOCTL_METHOD_OUT_DIRECT"
        $str3 = "IOCTL_SIOCTL_METHOD_IN_DIRECT"
        $str4 = "Windows (R) Win 7 DDK driver" wide
        $str5 = "Sample IOCTL Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

