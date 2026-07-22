rule Windows_VulnDriver_IdTech_a8be9539 {
    meta:
        author = "Elastic Security"
        id = "a8be9539-47ab-43d5-b15e-5b65104504c4"
        fingerprint = "3e7c4fcb4d6eaaabcd9a252c6460b6c1fbb44cb1d83ea8fe3473c91addd7cd84"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: ID TECH"
        threat_name = "Windows.VulnDriver.IdTech"
        reference_sample = "6a374d023813382fb79b447c05f3382f9d0bbb13f8ab0c1f8e8168f4a23d5ffe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 44 20 54 45 43 48 }
        $str1 = "msrhook.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_IdTech_ac7ed394 {
    meta:
        author = "Elastic Security"
        id = "ac7ed394-f4ab-404a-a46f-18e2dc996552"
        fingerprint = "75ef20305a2c94f62f2062c41996a812dc1b029207461cb55b8d3d5936f0c9c2"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: ID Tech"
        threat_name = "Windows.VulnDriver.IdTech"
        reference_sample = "a0ba1c981dcf3930680c97664efce6142679bd84604c38eb8b8368f6c1bde3c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 44 20 54 65 63 68 }
        $str1 = "msrhook.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

