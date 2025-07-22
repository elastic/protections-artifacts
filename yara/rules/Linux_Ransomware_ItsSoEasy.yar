rule Linux_Ransomware_ItsSoEasy_30bd68e0 {
  meta:
    author           = "Elastic Security"
    id               = "30bd68e0-3050-4aaf-b1bb-3ae10b6bd6dd"
    fingerprint      = "33170bbe6d182b36c77d732c283377f6f84cf82bd8d28cc4c3aef4d0914a0ae8"
    creation_date    = "2023-07-28"
    last_modified    = "2024-02-13"
    threat_name      = "Linux.Ransomware.ItsSoEasy"
    reference_sample = "efb1024654e86c0c30d2ac5f97d27f5f27b4dd3f7f6ada65d58691f0d703461c"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a1 = "main.encryptData.func1"
    $a2 = "main.makeAutoRun"

  condition:
    all of them
}

