rule Windows_VulnDriver_LittleOrbit_cbb1f862 {
    meta:
        author = "Elastic Security"
        id = "cbb1f862-dd9e-46be-a266-974ff29649c3"
        fingerprint = "51aed275520c44b95d0969f53dc249705941721014a290f76208b782c8434b30"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Little Orbit Inc"
        threat_name = "Windows.VulnDriver.LittleOrbit"
        reference_sample = "b6748d7da5759dee7d5f2f32b0326b4edb7b2135a0e4a6d5ff26aef1e139d8b2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 69 74 74 6C 65 20 4F 72 62 69 74 20 49 6E 63 }
        $str1 = "GFAC_Sys_x64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

