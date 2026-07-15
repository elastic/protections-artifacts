rule Windows_VulnDriver_DitMco_31fabc5e {
    meta:
        author = "Elastic Security"
        id = "31fabc5e-4fd9-45a1-bae6-a92906f5ac1f"
        fingerprint = "83ce10baf340a7ba7c1f403757a3fec40f30228fdbb933a435d3ae4b8a1fd4ef"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: DIT-MCO International Corporation"
        threat_name = "Windows.VulnDriver.DitMco"
        reference_sample = "33f9f2aa566d0873777e841c8cd970298a93206d3be4dfd30fee726eb0d47585"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 49 54 2D 4D 43 4F 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "DITPIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

