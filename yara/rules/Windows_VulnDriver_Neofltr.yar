rule Windows_VulnDriver_Neofltr_e89afd9f {
    meta:
        author = "Elastic Security"
        id = "e89afd9f-3803-465f-ad97-2ee0c004cac2"
        fingerprint = "ac51ce6c78cbe0cd3a50db055828732086f650f18052244d68b081a70c33718e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Ivanti, Inc., Version: <= 22.7.10.10"
        threat_name = "Windows.VulnDriver.Neofltr"
        reference_sample = "37507cdb5df5669862f0213feb521dc82a3c87b85c5489bbffdaedd1c43da132"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 76 61 6E 74 69 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 6F 00 66 00 6C 00 74 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x15][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x16-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x16-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00]|[\x07-\x07][\x00-\x00][\x16-\x16][\x00-\x00][\x00-\x09][\x00-\x00][\x0a-\x0a][\x00-\x00]|[\x07-\x07][\x00-\x00][\x16-\x16][\x00-\x00][\x0a-\x0a][\x00-\x00][\x0a-\x0a][\x00-\x00])/
        $str1 = "jnprTdi.pdb"
        $str2 = "IOCTL_W32API_SET_NETBIOS_NAME_QUERY_EVENT"
        $str3 = "IOCTL_W32API_GET_CONNECTION_LIST_ENTRIES"
        $str4 = "Secure Application Manager" wide
        $str5 = "NetBIOS Redirector" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

