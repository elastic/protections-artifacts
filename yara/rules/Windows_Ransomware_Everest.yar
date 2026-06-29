rule Windows_Ransomware_Everest_13b84bdd {
    meta:
        author = "Elastic Security"
        id = "13b84bdd-950c-4d8c-8a63-63d67a6209ed"
        fingerprint = "d1edac3097b4aea54c5d5d5542932e7bfdb3c7d84b5202f5e4c77bcf64cf6637"
        creation_date = "2026-06-16"
        last_modified = "2026-06-26"
        threat_name = "Windows.Ransomware.Everest"
        reference_sample = "1df92bf4c967297d8a39fc3f619a56702ee96d5cf9196b8e1d5b3654746c6514"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "EVERESTRANSOMWARE.txt" wide fullword
        $str2 = "Greetings from the Everest team." wide fullword
        $str3 = ".everest" wide fullword
    condition:
        3 of them
}

