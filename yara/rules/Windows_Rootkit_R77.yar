rule Windows_Rootkit_R77_5bab748b {
    meta:
        author = "Elastic Security"
        id = "5bab748b-8576-4967-9b50-a3778db1dd71"
        fingerprint = "2523d25c46bbb9621f0eceeda10aff31e236ed0bf03886de78524bdd2d39cfaa"
        creation_date = "2022-03-04"
        last_modified = "2022-04-12"
        threat_name = "Windows.Rootkit.R77"
        reference_sample = "cfc76dddc74996bfbca6d9076d2f6627912ea196fdbdfb829819656d4d316c0c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 01 04 10 41 8B 4A 04 49 FF C1 48 8D 41 F8 48 D1 E8 4C 3B C8 }
    condition:
        all of them
}

