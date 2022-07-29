rule Linux_Trojan_Adlibrary_0287a105 {
    meta:
        id = "0287a105-a1ba-4256-bfcf-aad40e6070ed"
        fingerprint = "bb12e72441f87971febb50141e3f520c1858220b081c2b0587dd8f1fac29b4ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Adlibrary"
        reference_sample = "acb22b88ecfb31664dc07b2cb3490b78d949cd35a67f3fdcd65b1a4335f728f1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 07 2A 00 00 F4 9F 01 00 07 2B 00 00 F8 9F 01 00 07 2C 00 00 }
    condition:
        all of them
}

