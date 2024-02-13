rule Linux_Ransomware_Akira_02237952 {
    meta:
        author = "Elastic Security"
        id = "02237952-b9ac-44e5-a32f-f3cc8f28a89b"
        fingerprint = "7fcfac47be082441f6df149d0615a9d2020ac1e9023eabfcf10db4fe400cd474"
        creation_date = "2023-07-28"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Akira"
        reference_sample = "1d3b5c650533d13c81e325972a912e3ff8776e36e18bca966dae50735f8ab296"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "No path to encrypt" fullword
        $a2 = "--encryption_percent" fullword
        $a3 = "Failed to import public key" fullword
        $a4 = "akira_readme.txt" fullword
    condition:
        3 of them
}

