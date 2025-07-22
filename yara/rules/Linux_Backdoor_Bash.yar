rule Linux_Backdoor_Bash_e427876d {
  meta:
    author           = "Elastic Security"
    id               = "e427876d-c7c5-447a-ad6d-5cbc12d9dacf"
    fingerprint      = "6cc13bb2591d896affc58f4a22b3463a72f6c9d896594fe1714b825e064b0956"
    creation_date    = "2021-01-12"
    last_modified    = "2021-09-16"
    threat_name      = "Linux.Backdoor.Bash"
    reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = "geDokKGlkIC11KTogL2V"

  condition:
    all of them
}

