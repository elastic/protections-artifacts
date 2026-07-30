rule Windows_VulnDriver_ProcObsrvesx_9ab6880d {
    meta:
        author = "Elastic Security"
        id = "9ab6880d-dca8-4324-89ec-6304740f58fa"
        fingerprint = "ab2c48bef56f6da5cc2b941bfc6d6303fa405a8b1eb0857c2ca4f24b85bba2ae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: MicroWorld Technologies Inc., Version: <= 4.0.0.49"
        threat_name = "Windows.VulnDriver.ProcObsrvesx"
        reference_sample = "37206b758eac2c7775ef881c1dc9a96129a517069bdf47049afc3b29e328408e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 57 6F 72 6C 64 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 72 00 6F 00 63 00 4F 00 62 00 73 00 72 00 76 00 65 00 73 00 78 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x30][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00][\x31-\x31][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "procobsrvesx.pdb"
        $str2 = "IOCTL_CLOSE_FILE_HANDLE_64"
        $str3 = "eScan/eConceal" wide
        $str4 = "ProcObsrvesx" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

