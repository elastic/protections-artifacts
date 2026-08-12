rule Linux_Trojan_DogLeash_49de92d8 {
    meta:
        author = "Elastic Security"
        id = "49de92d8-9b01-44a0-b120-c5bec880f11a"
        fingerprint = "d545bdd9240439a4d0887d6ce69081b9ebc7ad15483aa607917d91906cdc2271"
        creation_date = "2026-07-29"
        last_modified = "2026-08-10"
        threat_name = "Linux.Trojan.DogLeash"
        reference_sample = "dc4f25b2247cfdd6fc96848db30a178baa4419a4c854e86e315b465836102d14"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $fmt_hidden = "%s/.%d_%d"
        $code_cmd_switch_le = { 9A DD 42 24 0F 00 43 2C }
        $code_cmd_96xx_le = { 54 96 03 34 ?? ?? 43 10 55 96 03 34 2A 20 43 00 }
        $code_status_ffc_le = { FC 0F 02 3C 00 C2 42 34 }
        $code_cmd_3343_le = { 43 33 03 24 ?? ?? 43 10 50 34 03 24 }
        $code_cmd_switch_be = { 24 42 DD 9A 2C 43 00 0F }
        $code_cmd_96xx_be = { 34 03 96 54 10 43 ?? ?? 34 03 96 55 00 43 20 2A }
        $code_status_ffc_be = { 3C 02 0F FC 34 42 C2 00 }
        $code_cmd_3343_be = { 24 03 33 43 10 43 ?? ?? 24 03 34 50 }
    condition:
        3 of ($code*) or ($fmt_hidden and 2 of ($code*))
}

