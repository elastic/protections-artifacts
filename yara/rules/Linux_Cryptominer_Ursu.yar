rule Linux_Cryptominer_Ursu_3c05f8ab {
  meta:
    author           = "Elastic Security"
    id               = "3c05f8ab-d1b8-424b-99b7-1fe292ae68ff"
    fingerprint      = "463d4f675589e00284103ef53d0749539152bbc3772423f89a788042805b3a21"
    creation_date    = "2021-01-12"
    last_modified    = "2021-09-16"
    threat_name      = "Linux.Cryptominer.Ursu"
    reference_sample = "d72361010184f5a48386860918052dbb8726d40e860ea0287994936702577956"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = "dUL, \n\t0x302860782878"

  condition:
    all of them
}

