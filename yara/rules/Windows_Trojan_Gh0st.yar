rule Windows_Trojan_Gh0st_ee6de6bc {
  meta:
    author           = "Elastic Security"
    id               = "ee6de6bc-1648-4a77-9607-e2a211c7bda4"
    fingerprint      = "3c529043f34ad8a8692b051ad7c03206ce1aafc3a0eb8fcf7f5bcfdcb8c1b455"
    creation_date    = "2021-06-10"
    last_modified    = "2021-08-23"
    description      = "Identifies a variant of Gh0st Rat"
    threat_name      = "Windows.Trojan.Gh0st"
    reference_sample = "ea1dc816dfc87c2340a8b8a77a4f97618bccf19ad3b006dce4994be02e13245d"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1 = ":]%d-%d-%d  %d:%d:%d" ascii fullword
    $a2 = "[Pause Break]" ascii fullword
    $a3 = "f-secure.exe" ascii fullword
    $a4 = "Accept-Language: zh-cn" ascii fullword

  condition:
    all of them
}

rule Windows_Trojan_Gh0st_9e4bb0ce {
  meta:
    author           = "Elastic Security"
    id               = "9e4bb0ce-b1ed-45dc-8d86-943eb76f0bb4"
    fingerprint      = "4fb0eafc58972ef6fef87a88e43ae320420d760f545a66aab28dc3a65f629631"
    creation_date    = "2025-05-08"
    last_modified    = "2025-05-27"
    threat_name      = "Windows.Trojan.Gh0st"
    reference_sample = "2d93a17f04bf2fcd51c2142043af3840895ae7ba43909a26420c4879d214a3c3"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1  = "PluginMe" ascii fullword
    $a2  = "\\cmd.exe -Puppet" ascii fullword
    $a3  = "ERROR 1" ascii fullword
    $a4  = "ERROR 2" ascii fullword
    $a5  = "AYAgent.aye" ascii fullword
    $a6  = "mssecess.exe" ascii fullword
    $a7  = "shell\\open\\command" ascii fullword
    $a8  = "WinSta0\\Default" ascii fullword
    $a9  = { C6 44 24 ?? 53 C6 44 24 ?? 74 C6 44 24 ?? 61 C6 44 24 ?? 30 C6 44 24 ?? 5C }
    $a10 = { C6 44 24 ?? 41 C6 44 24 ?? 6C C6 44 24 ?? 69 C6 44 24 ?? 63 C6 44 24 ?? 61 C6 44 24 ?? 74 C6 44 24 ?? 69 }
    $a11 = { C6 44 24 ?? 2F C6 44 24 ?? 34 C6 44 24 ?? 2E C6 44 24 ?? 30 C6 44 24 ?? 20 C6 44 24 ?? 28 C6 44 24 ?? 63 }
    $a12 = "%c%c%c%c%c%c" ascii fullword
    $a13 = { 25 2D 32 34 73 20 25 2D 31 35 00 }

  condition:
    5 of them
}

