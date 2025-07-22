rule Windows_Trojan_DragonBreath_b27bc56b {
  meta:
    author           = "Elastic Security"
    id               = "b27bc56b-41a2-4b3d-bff4-a14b90debe08"
    fingerprint      = "4bc82f64191cf907d7ecf7da5453258c9be60e5dbaff770ebc22d9629bcbc7e2"
    creation_date    = "2024-06-05"
    last_modified    = "2024-06-12"
    threat_name      = "Windows.Trojan.DragonBreath"
    reference_sample = "45023fd0e694d66c284dfe17f78c624fd7e246a6c36860a0d892d232a30949be"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1 = "PluginMe"
    $a2 = "isARDll"
    $a3 = "%d-%d-%d %d:%d"

  condition:
    all of them
}

