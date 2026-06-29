rule Windows_VulnDriver_AsUpIO_beb325a3 {
    meta:
        author = "Elastic Security"
        id = "beb325a3-50bc-435f-bb3a-c023e1cf0a45"
        fingerprint = "df15c0196a6e45d3608bf457e5954cde14cc46379c51d8373a1737d9f5810667"
        creation_date = "2024-03-11"
        last_modified = "2026-06-25"
        threat_name = "Windows.VulnDriver.AsUpIO"
        reference_sample = "b9a4e40a5d80fedd1037eaed958f9f9efed41eb01ada73d51b5dcd86e27e0cbf"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = { 5C 00 44 00 6F 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5C 00 41 00 73 00 55 00 70 00 64 00 61 00 74 00 65 00 69 00 6F 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

