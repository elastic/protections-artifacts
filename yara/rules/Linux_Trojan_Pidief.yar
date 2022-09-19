rule Linux_Trojan_Pidief_635667d1 {
    meta:
        author = "Elastic Security"
        id = "635667d1-4b51-4e18-9e6b-5873194ce4f1"
        fingerprint = "29e1795f941990ca18fbe61154d3cfe23d43d13af298e763cd40fb9c40d7204e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Pidief"
        reference_sample = "e27ad676ae12188de7a04a3781aa487c11bab01d7848705bac5010d2735b19cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 06 4C 89 F7 FF 50 10 48 8B 45 00 48 89 EF FF 50 10 85 DB 75 15 4D }
    condition:
        all of them
}

