rule Windows_Trojan_GoldenGh0st_30206e56 {
    meta:
        author = "Elastic Security"
        id = "30206e56-c911-40d8-82e4-d9038e12fafc"
        fingerprint = "c025bb5acea95f7737e9a48bb29824e6de7baf4000e7ced18ac7781447197da1"
        creation_date = "2026-08-10"
        last_modified = "2026-08-17"
        threat_name = "Windows.Trojan.GoldenGh0st"
        reference = "https://x.com/elasticseclabs/status/2085057097188639162"
        reference_sample = "71685bdb5f5e67df6b1690eb21c63c75c7f910d8e25fac881532ee96e0461a6d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 63 68 6F 69 63 65 20 2F 44 20 79 20 2F 74 20 25 5F 70 72 6F 63 65 73 73 54 69 6D 65 6F 75 74 25 20 3E 20 6E 75 6C 0A 0D 29 0A 0D 00 }
        $b = { 69 66 20 22 25 6E 75 6D 25 22 20 4E 45 51 20 22 30 22 20 65 63 68 6F 20 25 5F 70 72 6F 63 65 73 73 4E 61 6D 65 25 20 69 73 20 72 75 6E 6E 69 6E 67 20 0A 0D 00 }
        $c = { 67 6F 74 6F 20 4C 4F 4F 50 0A 00 }
    condition:
        all of them
}

