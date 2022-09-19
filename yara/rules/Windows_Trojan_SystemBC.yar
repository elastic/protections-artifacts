rule Windows_Trojan_SystemBC_5e883723 {
    meta:
        author = "Elastic Security"
        id = "5e883723-7eaa-4992-91de-abb0ffbba54e"
        fingerprint = "add95c1f4bb279c8b189c3d64a0c2602c73363ebfad56a4077119af148dd2d87"
        creation_date = "2022-03-22"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.SystemBC"
        reference_sample = "b432805eb6b2b58dd957481aa8a973be58915c26c04630ce395753c6a5196b14"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GET /tor/rendezvous2/%s HTTP/1.0" ascii fullword
        $a2 = "https://api.ipify.org/" ascii fullword
        $a3 = "KEY-----" ascii fullword
        $a4 = "Host: %s" ascii fullword
        $a5 = "BEGINDATA" ascii fullword
        $a6 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
    condition:
        all of them
}

