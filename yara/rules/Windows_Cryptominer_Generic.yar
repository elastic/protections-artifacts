rule Windows_Cryptominer_Generic_dd1e4d1a {
    meta:
        author = "Elastic Security"
        id = "dd1e4d1a-2e2f-4af0-bd66-2e12367dd064"
        fingerprint = "a00e3e08e11d10a7a4bf1110a5110e4d0a4d2acf0974aca9dfc1ad5f21c80df7"
        creation_date = "2021-01-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Cryptominer.Generic"
        reference_sample = "7ac1d7b6107307fb2442522604c8fa56010d931392d606ac74dcea6b7125954b"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { EF F9 66 0F EF FA 66 0F FE FE 66 0F 6F B0 B0 00 00 00 66 0F }
    condition:
        all of them
}

