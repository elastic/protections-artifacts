rule Windows_Trojan_DustyWarehouse_a6cfc9f7 {
    meta:
        author = "Elastic Security"
        id = "a6cfc9f7-6d4a-4904-8294-790243eca76a"
        fingerprint = "a0ef31535c7df8669e2b0cf38e9128e662bf64decabac5c9f3dad3a98f811033"
        creation_date = "2023-08-25"
        last_modified = "2023-11-02"
        threat_name = "Windows.Trojan.DustyWarehouse"
        reference_sample = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%4d.%2d.%2d-%2d:%2d:%2d" wide fullword
        $a2 = ":]%d-%d-%d %d:%d:%d" wide fullword
        $a3 = "\\sys.key" wide fullword
        $a4 = "[rwin]" wide fullword
        $a5 = "Software\\Tencent\\Plugin\\VAS" fullword
    condition:
        3 of them
}

