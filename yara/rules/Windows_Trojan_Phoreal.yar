rule Windows_Trojan_Phoreal_66e91de3 {
  meta:
    author           = "Elastic Security"
    id               = "66e91de3-a510-4a64-b03d-5385ceb32360"
    fingerprint      = "36c9150137b3d65ea6127abe54571f7346c5ebffd1966bf0a9ff99406fe5aa24"
    creation_date    = "2022-02-16"
    last_modified    = "2022-04-12"
    threat_name      = "Windows.Trojan.Phoreal"
    reference        = "https://www.elastic.co/security-labs/phoreal-malware-targets-the-southeast-asian-financial-sector"
    reference_sample = "88f073552b30462a00d1d612b1638b0508e4ef02c15cf46203998091f0aef4de"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 7B 00 41 00 30 00 36 00 46 00 31 00 37 00 36 00 46 00 2D 00 37 00 39 00 46 00 31 00 2D 00 34 00 37 00 33 00 45 00 2D 00 41 00 46 00 34 00 34 00 2D 00 39 00 37 00 36 00 33 00 45 00 33 00 43 00 42 00 33 00 34 00 45 00 35 00 7D 00 }
    $a2 = { 4C 00 6F 00 63 00 61 00 6C 00 5C 00 7B 00 35 00 46 00 42 00 43 00 33 00 46 00 35 00 33 00 2D 00 41 00 37 00 36 00 44 00 2D 00 34 00 32 00 34 00 38 00 2D 00 39 00 36 00 39 00 41 00 2D 00 33 00 31 00 37 00 34 00 30 00 43 00 42 00 43 00 38 00 41 00 44 00 36 00 7D 00 }
    $a3 = "{FD5F8447-657A-45C1-894B-D533926C9B66}.dll"
    $b1 = { 8B FF 55 8B EC 56 E8 3F 3E 00 00 E8 34 3E 00 00 50 E8 14 3E 00 00 85 C0 75 2A 8B 75 08 56 E8 21 }

  condition:
    2 of them
}

