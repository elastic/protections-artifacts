rule Windows_VulnDriver_Safetica_ddcd5c47 {
    meta:
        author = "Elastic Security"
        id = "ddcd5c47-bad1-4a65-8dcb-848d220b90dd"
        fingerprint = "f147fad1d31a5643bb2acbeb735c50f7922658ab79244824d49b04a700cb0e70"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Safetica Technologies s.r.o., Version: <= 8.3.83.1"
        threat_name = "Windows.VulnDriver.Safetica"
        reference_sample = "079fb71163b99c452dc3c8917f0ce022ae82df1a2529bd8a60c0506c55be0754"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 66 65 74 69 63 61 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 54 00 50 00 72 00 6F 00 63 00 65 00 73 00 73 00 4D 00 6F 00 6E 00 69 00 74 00 6F 00 72 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x52][\x00-\x00]|[\x03-\x03][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\x00][\x00-\x00][\x53-\x53][\x00-\x00]|[\x03-\x03][\x00-\x00][\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x53-\x53][\x00-\x00])/
        $str1 = "ProcessMonitorDriver.pdb"
        $str2 = "ProcessMonitor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

