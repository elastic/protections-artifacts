rule Windows_VulnDriver_Exacq_79453d61 {
    meta:
        author = "Elastic Security"
        id = "79453d61-10cf-4941-a539-8bdd9d0dc05b"
        fingerprint = "d5b2e2b645855817f071480193281436287206e844bf76682f0bc9ef07b11fde"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Exacq Technologies, Inc."
        threat_name = "Windows.VulnDriver.Exacq"
        reference_sample = "15fb486b6b8c2a2f1b067f48fba10c2f164638fe5e6cee618fb84463578ecac9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 78 61 63 71 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 2C 20 49 6E 63 2E }
        $str1 = "WinioSys.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

