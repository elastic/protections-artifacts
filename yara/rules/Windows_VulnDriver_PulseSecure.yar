rule Windows_VulnDriver_PulseSecure_cab84a49 {
    meta:
        author = "Elastic Security"
        id = "cab84a49-6f59-4bc1-9ca4-ce88cab74caa"
        fingerprint = "821d189bc7efcc83886411a3dcca2209972e697cf541548b621ca42eb9687d74"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Pulse Secure, LLC, Version: <= 8.3.3.1350"
        threat_name = "Windows.VulnDriver.PulseSecure"
        reference_sample = "8dbc28fefb8cf9377be55a7c6062988df5a24f0ff475f6dd65cf07fe5173f51d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 75 6C 73 65 20 53 65 63 75 72 65 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 6F 00 66 00 6C 00 74 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x08-\x08][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x04]|[\x00-\x45][\x05-\x05])[\x03-\x03][\x00-\x00]|[\x03-\x03][\x00-\x00][\x08-\x08][\x00-\x00][\x46-\x46][\x05-\x05][\x03-\x03][\x00-\x00])/
        $str1 = "jnprTdi.pdb"
        $str2 = "IOCTL_W32API_SET_NETBIOS_NAME_QUERY_EVENT"
        $str3 = "IOCTL_W32API_GET_CONNECTION_LIST_ENTRIES"
        $str4 = "Secure Application Manager" wide
        $str5 = "NetBIOS Redirector" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

