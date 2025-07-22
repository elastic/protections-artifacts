rule Windows_Trojan_ShelbyLoader_ca4d5de6 {
  meta:
    author           = "Elastic Security"
    id               = "ca4d5de6-1b4f-4c5b-97aa-1d432aa870f7"
    fingerprint      = "95a2cf5388aa07c434ad23ed9e96cfa5c80a2eff030ccf48169142a28fbb63ee"
    creation_date    = "2025-03-11"
    last_modified    = "2025-03-25"
    threat_name      = "Windows.Trojan.ShelbyLoader"
    reference_sample = "0354862d83a61c8e69adc3e65f6e5c921523eff829ef1b169e4f0f143b04091f"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a0 = "[WARN] Unusual parent process detected: "
    $a1 = "[ERROR] Exception in CheckParentProcess:" fullword
    $a2 = "[INFO] Sandbox Not Detected by CheckParentProcess" fullword
    $b0 = "\"content\": \".+?\""
    $b1 = "\"sha\": \".+?\""
    $b2 = "Persist ID: " fullword
    $b3 = "https://api.github.com/repos/" fullword

  condition:
    all of ($a*) or all of ($b*)
}

