rule Windows_VulnDriver_Sivx64_2d3872ca {
    meta:
        author = "Elastic Security"
        id = "2d3872ca-8d1f-43f7-81d9-7b35e6e5377b"
        fingerprint = "a8f21b476b05a3aea4f062579a20617bbe509a66a8049f0318880bf1eceede82"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 5.85.0.0"
        threat_name = "Windows.VulnDriver.Sivx64"
        reference_sample = "33903e8fa9f0a2acaa4784d645e309b0bd780693824b6c2c5fef257238c77478"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 49 00 56 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x54][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x55-\x55][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SIVX64.pdb"
        $str2 = "IOCTL_SCSI_MINIPORT_READ_SMART_THRESHOLDS"
        $str3 = "IOCTL_SIV_MUTANT_OWNER"
        $str4 = "SIVDRIVER" wide
        $str5 = "System Information Viewer X64 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

