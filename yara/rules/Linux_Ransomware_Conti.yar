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

