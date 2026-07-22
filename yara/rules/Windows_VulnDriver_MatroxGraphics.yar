rule Windows_VulnDriver_MatroxGraphics_f069d0ed {
    meta:
        author = "Elastic Security"
        id = "f069d0ed-5f98-486d-bdd5-0bed9e53d42b"
        fingerprint = "453707599c0deb47f3d56c7497d723669d9b1a3547850ba88443005eb2837e4e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Matrox Graphics Inc."
        threat_name = "Windows.VulnDriver.MatroxGraphics"
        reference_sample = "0414c0d5bb6ddbcc84b3d59ce411acf1ed8b17d17054c6192e0a7594b5146d60"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 74 72 6F 78 20 47 72 61 70 68 69 63 73 20 49 6E 63 2E }
        $str1 = "MtxVxd.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

