rule Windows_Trojan_ShelbyC2_dae5bc1d {
  meta:
    author           = "Elastic Security"
    id               = "dae5bc1d-2011-446e-9909-935c0ef51e37"
    fingerprint      = "48013925624ad4572067e40b1751e181d678a96d894ec622470c7d65d33afbd6"
    creation_date    = "2025-03-11"
    last_modified    = "2025-03-25"
    threat_name      = "Windows.Trojan.ShelbyC2"
    reference_sample = "fb8d4c24bcfd853edb15c5c4096723b239f03255f17cec42f2d881f5f31b6025"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a0 = "File Uploaded Successfully" fullword
    $a1 = "/dlextract" fullword
    $a2 = "/evoke" fullword
    $a4 = "\"sha\": \".+?\""
    $a5 = "\",\"sha\":\""

  condition:
    all of them
}

