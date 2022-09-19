rule Linux_Trojan_Neshta_e856e9fb {
    meta:
        author = "Elastic Security"
        id = "e856e9fb-24b6-47bc-9e38-db50ff091aa9"
        fingerprint = "be36444e7cf3911d52960e28f83a04979b4669f56bc9fa7129ab852a1f17739b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Neshta"
        reference_sample = "d69378cbb14d524f38a9b33ceeff22cfeb74ed481ffffa8aa279713d050588ae"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F 66 20 70 72 6F 63 65 73 73 65 73 20 28 72 65 63 6F 6D 6D }
    condition:
        all of them
}

