rule Linux_Trojan_Skidmap_aa7b661d {
    meta:
        author = "Elastic Security"
        id = "aa7b661d-0ecc-4171-a0c2-a6c0c91b6d27"
        fingerprint = "0bd6bec14d4b0205b04c6b4f34988ad95161f954a1f0319dd33513cb2c7e5f59"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Skidmap"
        reference_sample = "4282ba9b7bee69d42bfff129fff45494fb8f7db0e1897fc5aa1e4265cb6831d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 41 41 80 F8 1A 41 0F 43 C1 88 04 0E 48 83 C1 01 0F B6 04 0F }
    condition:
        all of them
}

