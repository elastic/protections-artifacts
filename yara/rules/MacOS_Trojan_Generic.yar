rule MacOS_Trojan_Generic_a829d361 {
    meta:
        author = "Elastic Security"
        id = "a829d361-ac57-4615-b8e9-16089c44d7af"
        fingerprint = "5dba43dbc5f4d5ee295e65d66dd4e7adbdb7953232faf630b602e6d093f69584"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Generic"
        reference_sample = "5b2a1cd801ae68a890b40dbd1601cdfeb5085574637ae8658417d0975be8acb5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { E7 81 6A 12 EA A8 56 6C 86 94 ED F6 E8 D7 35 E1 EC 65 47 BA 8E 46 2C A6 14 5F }
    condition:
        all of them
}

