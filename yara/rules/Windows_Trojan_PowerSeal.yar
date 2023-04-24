rule Windows_Trojan_PowerSeal_d63f5e54 {
    meta:
        author = "Elastic Security"
        id = "d63f5e54-6be1-453d-a96e-083a025deba2"
        fingerprint = "bc63511a0b12edaf7a2ace02f79ab9a2dbea5a0879fd976cc91308f98bac1c52"
        creation_date = "2023-03-16"
        last_modified = "2023-04-23"
        threat_name = "Windows.Trojan.PowerSeal"
        reference_sample = "8d8bb9aac0a1fb4771994530ec81b9aa2f5af9f34322f353bba279b6c887e15e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PowerSeal.dll" wide fullword
        $a2 = "InvokePs" ascii fullword
        $a3 = "amsiInitFailed" wide fullword
        $a4 = "is64BitOperatingSystem" ascii fullword
    condition:
        all of them
}

