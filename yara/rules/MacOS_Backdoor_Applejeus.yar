rule MacOS_Backdoor_Applejeus_31872ae2 {
    meta:
        author = "Elastic Security"
        id = "31872ae2-f6df-4079-89c2-866cb2e62ec8"
        fingerprint = "24b78b736f691e6b84ba88b0bb47aaba84aad0c0e45cf70f2fa8c455291517df"
        creation_date = "2021-10-18"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Backdoor.Applejeus"
        reference_sample = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { FF CE 74 12 89 F0 31 C9 80 34 0F 63 48 FF C1 48 39 C8 75 F4 }
    condition:
        all of them
}

