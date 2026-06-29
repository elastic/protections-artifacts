rule Windows_VulnDriver_Binalyze_b487a1d3 {
    meta:
        author = "Elastic Security"
        id = "b487a1d3-9bd5-4124-918c-adf2c34f8c5b"
        fingerprint = "f79f9430d506f1d660ba682718ae7db6c20c61d40c3423227afd8a658615f6dc"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Binalyze LLC"
        threat_name = "Windows.VulnDriver.Binalyze"
        reference_sample = "b0e23d981bbfbc5a99e7f87f9ed987cadecc6a427ba1034fb06af47f04be6c1d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 69 6E 61 6C 79 7A 65 20 4C 4C 43 }
        $str1 = "irec64.pdb"
        $str2 = "IOCTL_CREATE_OBJECT_DIRECTORY_SNAPSHOT_RESPONSE"
        $str3 = "IOCTL_CREATE_OBJECT_DIRECTORY_SNAPSHOT_REQUEST"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

