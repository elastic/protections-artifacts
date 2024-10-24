rule Windows_Trojan_Xeno_f92ffb82 {
    meta:
        author = "Elastic Security"
        id = "f92ffb82-b743-4df1-9d6b-2afa3b7bb61f"
        fingerprint = "2ae1aebd652afb7da5799f46883205b1f3a5c5b01e975b526640407d9bd0d22c"
        creation_date = "2024-10-10"
        last_modified = "2024-10-24"
        threat_name = "Windows.Trojan.Xeno"
        reference_sample = "22dbdbcdd4c8b6899006f9f07e87c19b6a2947eeff8cc89c653309379b388cf4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 7D 0E 00 00 04 02 7B 0E 00 00 04 28 29 00 00 0A 07 7B 03 00 00 04 02 7B 0E 00 00 04 6F 2A 00 00 0A 3A F2 00 00 00 02 7B 07 00 00 04 02 7B 09 00 00 04 6F 32 00 00 06 6F 2B 00 00 0A }
    condition:
        all of them
}

