rule Windows_Trojan_Njrat_30f3c220 {
    meta:
        author = "Elastic Security"
        id = "30f3c220-b8dc-45a1-bcf0-027c2f76fa63"
        fingerprint = "d15e131bca6beddcaecb20fffaff1784ad8a33a25e7ce90f7450d1a362908cc4"
        creation_date = "2021-06-13"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Njrat"
        reference_sample = "741a0f3954499c11f9eddc8df7c31e7c59ca41f1a7005646735b8b1d53438c1b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "get_Registry" ascii fullword
        $a2 = "SEE_MASK_NOZONECHECKS" wide fullword
        $a3 = "Download ERROR" wide fullword
        $a4 = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
        $a5 = "netsh firewall delete allowedprogram \"" wide fullword
        $a6 = "[+] System : " wide fullword
    condition:
        3 of them
}

