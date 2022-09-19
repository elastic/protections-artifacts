rule Windows_Trojan_Netwire_6a7df287 {
    meta:
        author = "Elastic Security"
        id = "6a7df287-1656-4779-9a96-c0ab536ae86a"
        fingerprint = "85051a0b94da4388eaead4c4f4b2d16d4a5eb50c3c938b3daf5c299c9c12f1e6"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Netwire"
        reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0F B6 74 0C 10 89 CF 29 C7 F7 C6 DF 00 00 00 74 09 41 89 F3 88 5C }
    condition:
        all of them
}

rule Windows_Trojan_Netwire_1b43df38 {
    meta:
        author = "Elastic Security"
        id = "1b43df38-886e-4f58-954a-a09f30f19907"
        fingerprint = "4142ea14157939dc23b8d1f5d83182aef3a5877d2506722f7a2706b7cb475b76"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Netwire"
        reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
        $a2 = "\\Login Data"
        $a3 = "SOFTWARE\\NetWire" fullword
    condition:
        2 of them
}

