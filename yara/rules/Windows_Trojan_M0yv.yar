rule Windows_Trojan_M0yv_92f66467 {
  meta:
    author           = "Elastic Security"
    id               = "92f66467-89fd-4501-b045-3c6aed6c82f9"
    fingerprint      = "2afebc9478fbad18b74748794773cae9be3a4eac599d657bab5a7f8de331ba41"
    creation_date    = "2023-05-03"
    last_modified    = "2023-06-13"
    threat_name      = "Windows.Trojan.M0yv"
    reference_sample = "0004d22dd18c0239b722c085101c0a32b967159e2066a0b7b9104bb43f5cdea0"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1 = "Te}Ainc]jhm"
    $a2 = "NsMbbwanfwXrardl}"
    $a3 = "@e}AincHwqziftugzU"

  condition:
    all of them
}

