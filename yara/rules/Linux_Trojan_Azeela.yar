rule Linux_Trojan_Azeela_aad9d6cc {
    meta:
        author = "Elastic Security"
        id = "aad9d6cc-32ff-431a-9914-01c7adc80877"
        fingerprint = "3b7c73a378157350344d52acd6c210d5924cf55081b386d0d60345e4c44c5921"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Azeela"
        reference_sample = "6c476a7457ae07eca3d3d19eda6bb6b6b3fa61fa72722958b5a77caff899aaa6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 74 07 B8 01 00 00 00 EB 31 48 8B 45 F8 0F B6 00 3C FF 74 21 48 83 45 }
    condition:
        all of them
}

