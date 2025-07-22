rule Linux_Ransomware_EchoRaix_ea9532df {
  meta:
    author           = "Elastic Security"
    id               = "ea9532df-1136-4b11-bf4f-8838074f4e66"
    fingerprint      = "f28b340b99ec2b96ee78da50b3fc455c87dca1e898abf008c16ac192556939c5"
    creation_date    = "2023-07-27"
    last_modified    = "2024-02-13"
    threat_name      = "Linux.Ransomware.EchoRaix"
    reference_sample = "dfe32d97eb48fb2afc295eecfda3196cba5d27ced6217532d119a764071c6297"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = "CXhdKtzeBYlHeXyZRba0/neFz4IzgS8Lhu68ZuLLR/fgnr4yTrZTkC61b-YolI/2L6fSUFRrUpI4mNSAOb_"

  condition:
    all of them
}

rule Linux_Ransomware_EchoRaix_ee0c719a {
  meta:
    author           = "Elastic Security"
    id               = "ee0c719a-1f04-45ff-9e49-38028b138fd0"
    fingerprint      = "073d62ce55b1940774ffadeb5b76343aa49bd0a36cf82d50e2bae44f6049a1e8"
    creation_date    = "2023-07-29"
    last_modified    = "2024-02-13"
    threat_name      = "Linux.Ransomware.EchoRaix"
    reference_sample = "e711b2d9323582aa390cf34846a2064457ae065c7d2ee1a78f5ed0859b40f9c0"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a1 = { 24 10 89 44 24 68 8B 4C 24 14 8B 54 24 18 85 C9 74 57 74 03 8B }
    $a2 = "main.CheckIsRunning"

  condition:
    all of them
}

