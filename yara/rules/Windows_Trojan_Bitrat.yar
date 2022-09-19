rule Windows_Trojan_Bitrat_34bd6c83 {
    meta:
        author = "Elastic Security"
        id = "34bd6c83-9a71-43d5-b0b1-1646a8fb66e8"
        fingerprint = "bc4a5fad1810ad971277a455030eed3377901a33068bb994e235346cfe5a524f"
        creation_date = "2021-06-13"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Bitrat"
        reference_sample = "37f70ae0e4e671c739d402c00f708761e98b155a1eefbedff1236637c4b7690a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "crd_logins_report" ascii fullword
        $a2 = "drives_get" ascii fullword
        $a3 = "files_get" ascii fullword
        $a4 = "shell_stop" ascii fullword
        $a5 = "hvnc_start_ie" ascii fullword
    condition:
        all of them
}

