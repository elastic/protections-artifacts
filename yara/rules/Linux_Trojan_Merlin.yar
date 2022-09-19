rule Linux_Trojan_Merlin_55beddd3 {
    meta:
        author = "Elastic Security"
        id = "55beddd3-735b-4e0c-a387-e6a981cd42a3"
        fingerprint = "54e03337930d74568a91e797cfda3b7bfbce3aad29be2543ed58c51728d8e185"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "15ccdf2b948fe6bd3d3a7f5370e72cf3badec83f0ec7f47cdf116990fb551adf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }
    condition:
        all of them
}

