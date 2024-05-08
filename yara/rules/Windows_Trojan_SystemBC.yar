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

rule Windows_Trojan_SystemBC_c1b58c2f {
    meta:
        author = "Elastic Security"
        id = "c1b58c2f-8bbf-4c03-9f53-13ab2fb081cc"
        fingerprint = "dfbf98554e7fb8660e4eebd6ad2fadc394fc2a4168050390370ec358f6af1c1d"
        creation_date = "2024-05-02"
        last_modified = "2024-05-08"
        threat_name = "Windows.Trojan.SystemBC"
        reference_sample = "016fc1db90d9d18fe25ed380606346ef12b886e1db0d80fe58c22da23f6d677d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GET %s HTTP/1.0" ascii fullword
        $a2 = "HOST1:"
        $a3 = "PORT1:"
        $a4 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
        $a5 = "BEGINDATA" ascii fullword
        $a6 = "socks32.dll" ascii fullword
    condition:
        5 of them
}

