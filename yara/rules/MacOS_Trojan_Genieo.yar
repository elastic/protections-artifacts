rule MacOS_Trojan_Genieo_5e0f8980 {
  meta:
    author           = "Elastic Security"
    id               = "5e0f8980-1789-4763-9e41-a521bdb3ff34"
    fingerprint      = "f0b5198ce85d19889052a7e33fb7cf32a7725c4fdb384ffa7d60d209a7157092"
    creation_date    = "2021-10-05"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Trojan.Genieo"
    reference_sample = "6c698bac178892dfe03624905256a7d9abe468121163d7507cade48cf2131170"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a = { 00 CD 01 1E 68 57 58 D7 56 7C 62 C9 27 3C C6 15 A9 3D 01 02 2F E1 69 B5 4A 11 }

  condition:
    all of them
}

rule MacOS_Trojan_Genieo_37878473 {
  meta:
    author           = "Elastic Security"
    id               = "37878473-b6f8-4cbe-ba70-31ecddf41c82"
    fingerprint      = "e9760bda6da453f75e543c919c260a4560989f62f3332f28296283d4c01b62a2"
    creation_date    = "2021-10-05"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Trojan.Genieo"
    reference_sample = "0fadd926f8d763f7f15e64f857e77f44a492dcf5dc82ae965d3ddf80cd9c7a0d"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a = "ernalDownLoadUrlForBrand:]"

  condition:
    all of them
}

rule MacOS_Trojan_Genieo_0d003634 {
  meta:
    author           = "Elastic Security"
    id               = "0d003634-8b17-4e26-b4a2-4bfce2e64dde"
    fingerprint      = "6f38b7fc403184482449957aff51d54ac9ea431190c6f42c7a5420efbfdb8f7d"
    creation_date    = "2021-10-05"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Trojan.Genieo"
    reference_sample = "bcd391b58338efec4769e876bd510d0c4b156a7830bab56c3b56585974435d70"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a = "uild/AnabelPackage/build/s"

  condition:
    all of them
}

rule MacOS_Trojan_Genieo_9e178c0b {
  meta:
    author           = "Elastic Security"
    id               = "9e178c0b-02ca-499b-93d1-2b6951d41435"
    fingerprint      = "b00bffbdac79c5022648bf8ca5a238db7e71f3865a309f07d068ee80ba283b82"
    creation_date    = "2021-10-05"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Trojan.Genieo"
    reference_sample = "b7760e73195c3ea8566f3ff0427d85d6f35c6eec7ee9184f3aceab06da8845d8"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a = "MIpgAYKkBZYSeMkapABHMZCcDD"

  condition:
    all of them
}

