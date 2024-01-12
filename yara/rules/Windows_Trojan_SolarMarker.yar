rule Windows_Trojan_SolarMarker_d466e548 {
    meta:
        author = "Elastic Security"
        id = "d466e548-eb88-41e6-9740-ae59980db835"
        fingerprint = "0f4b0162ee8283959e10c459ddc55eb00eae30d241119aad1aa3ea6c101f9889"
        creation_date = "2023-12-12"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.SolarMarker"
        reference_sample = "330f5067c93041821be4e7097cf32fb569e2e1d00e952156c9aafcddb847b873"
        reference_sample = "e2a620e76352fa7ac58407a711821da52093d97d12293ae93d813163c58eb84b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 00 2B 03 00 2B 15 00 07 2D 09 08 16 FE 01 16 FE 01 2B 01 17 00 13 04 11 04 2D 8C 07 2D 06 08 }
    condition:
        all of them
}

