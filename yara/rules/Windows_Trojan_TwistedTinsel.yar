rule Windows_Trojan_TwistedTinsel_aa56e527 {
  meta:
    author           = "Elastic Security"
    id               = "aa56e527-df1a-4db7-ad89-187dff5e8745"
    fingerprint      = "e78a92c34ce7ab5545cd44930839551f72d8b19256d4f3280aad81358233f9eb"
    creation_date    = "2023-12-06"
    last_modified    = "2024-01-12"
    threat_name      = "Windows.Trojan.TwistedTinsel"
    reference_sample = "ef1cbdf9a23ae028a858e1d09529982eaeda61197ae029e091918690d3a86e2e"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1 = "C:\\ProgramData\\Microsoft\\EdgeUpdate\\Log\\chuangkou.log"
    $a2 = { 55 8B EC 83 EC 20 C7 45 EC 01 00 00 00 8B 45 08 8B 48 04 89 4D F4 8B 55 08 8B 02 B9 08 00 00 00 C1 E1 00 8D 54 08 78 89 55 E4 8B 45 E4 83 78 04 00 0F 86 81 01 00 00 8B 4D E4 8B 55 F4 03 11 89 }

  condition:
    any of them
}

