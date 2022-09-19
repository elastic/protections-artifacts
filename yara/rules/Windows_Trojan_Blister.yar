rule Windows_Trojan_Blister_cb99a1df {
    meta:
        author = "Elastic Security"
        id = "cb99a1df-756b-46fe-b657-63b4be2c0664"
        fingerprint = "7a7e189ed42019636ffccc06d61e18f2aa17bc3d43d08d50bb77c3258bc1a9a4"
        creation_date = "2021-12-21"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "0a7778cf6f9a1bd894e89f282f2e40f9d6c9cd4b72be97328e681fe32a1b1a00"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 8D 45 DC 89 5D EC 50 6A 04 8D 45 F0 50 8D 45 EC 50 6A FF FF D7 }
        $a2 = { 75 F7 39 4D FC 0F 85 F3 00 00 00 64 A1 30 00 00 00 53 57 89 75 }
        $b1 = { 78 03 C3 8B 48 20 8B 50 1C 03 CB 8B 78 24 03 D3 8B 40 18 03 FB 89 4D F8 89 55 E0 89 45 E4 85 C0 74 3E 8B 09 8B D6 03 CB 8A 01 84 C0 74 17 C1 C2 09 0F BE C0 03 D0 41 8A 01 84 C0 75 F1 81 FA B2 17 EB 41 74 27 8B 4D F8 83 C7 02 8B 45 F4 83 C1 04 40 89 4D F8 89 45 F4 0F B7 C0 3B 45 E4 72 C2 8B FE 8B 45 04 B9 }
    condition:
        any of them
}

rule Windows_Trojan_Blister_9d757838 {
    meta:
        author = "Elastic Security"
        id = "9d757838-ebaa-4ecf-b927-ac0f4848c9cb"
        fingerprint = "4ef2e22d0006b127b253d02073cde0d805d22d8696562feabc94020e287e2eb2"
        creation_date = "2022-04-26"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "863de84a39c9f741d8103db83b076695d0d10a7384e4e3ba319c05a6018d9737"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 65 48 8B 04 25 60 00 00 00 44 0F B7 DB 48 8B 48 ?? 48 8B 41 ?? C7 45 48 ?? ?? ?? ?? 4C 8B 40 ?? 49 63 40 ?? }
        $a2 = { B9 FF FF FF 7F 89 5D 40 8B C1 44 8D 63 ?? F0 44 01 65 40 49 2B C4 75 ?? 39 4D 40 0F 85 ?? ?? ?? ?? 65 48 8B 04 25 60 00 00 00 44 0F B7 DB }
    condition:
        any of them
}

