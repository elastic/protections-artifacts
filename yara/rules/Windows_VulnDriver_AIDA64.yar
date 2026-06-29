rule Windows_VulnDriver_AIDA64_9ea4f9f2 {
    meta:
        author = "Elastic Security"
        id = "9ea4f9f2-f9b9-49cd-837d-f05740b754ac"
        fingerprint = "d83240610fee1a5bd24466c8a8103acf2b0111c1723fb4a149ee2c52d6c363bf"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: LAVALYS"
        threat_name = "Windows.VulnDriver.AIDA64"
        reference_sample = "065a34b786b0ccf6f88c136408943c3d2bd3da14357ee1e55e81e05d67a4c9bc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 41 56 41 4C 59 53 }
        $str1 = "LLKD.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

