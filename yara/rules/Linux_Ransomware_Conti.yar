rule Linux_Ransomware_Conti_53a640f4 {
    meta:
        author = "Elastic Security"
        id = "53a640f4-905c-4b0d-ac4a-9ffdffd74253"
        fingerprint = "d81309f83494b0635444234c514fda0edc05a11ac861c769a007f9f558def148"
        creation_date = "2022-09-22"
        last_modified = "2022-10-18"
        threat_name = "Linux.Ransomware.Conti"
        reference_sample = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 D3 EA 48 89 D0 83 E0 01 48 85 C0 0F 95 C0 84 C0 74 0B 8B }
    condition:
        all of them
}

rule Linux_Ransomware_Conti_a89c26cf {
    meta:
        author = "Elastic Security"
        id = "a89c26cf-ccec-40ca-85d3-d014b767fd6a"
        fingerprint = "c29bb1bbbd76712bbc3ddd1dfeeec40b230677339dea7441b1f34159ccbbdf9f"
        creation_date = "2023-07-30"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Conti"
        reference_sample = "95776f31cbcac08eb3f3e9235d07513a6d7a6bf9f1b7f3d400b2cf0afdb088a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "paremeter --size cannot be %d" fullword
        $a2 = "--vmkiller" fullword
        $a3 = ".conti" fullword
        $a4 = "Cannot create file vm-list.txt" fullword
    condition:
        3 of them
}

