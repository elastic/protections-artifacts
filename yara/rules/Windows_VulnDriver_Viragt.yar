rule Windows_VulnDriver_Viragt_5f92f226 {
  meta:
    author           = "Elastic Security"
    id               = "5f92f226-053e-4a5b-8a0c-52a578f66cb8"
    fingerprint      = "544d7012478f31e9f9858ddb4463fa705bf8d50a97b5477557bd95e2d3d3b3ac"
    creation_date    = "2022-04-07"
    last_modified    = "2022-04-07"
    description      = "Name: viragt.sys, Version: 1.80.0.0"
    threat_name      = "Windows.VulnDriver.Viragt"
    reference_sample = "e05eeb2b8c18ad2cb2d1038c043d770a0d51b96b748bc34be3e7fc6f3790ce53"
    severity         = 50
    arch_context     = "x86"
    scan_context     = "file"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 69 00 72 00 61 00 67 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
    $version            = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x50][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x4f][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

  condition:
    int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Viragt_84d508ad {
  meta:
    author           = "Elastic Security"
    id               = "84d508ad-939d-4e3b-b9a6-204eb8bcaee5"
    fingerprint      = "172be67b6bb07f189fd5e535e173d245114bf4b17c3daf89924a30c7219d3e69"
    creation_date    = "2022-04-07"
    last_modified    = "2022-04-07"
    description      = "Name: viragt64.sys, Version: 1.0.0.11"
    threat_name      = "Windows.VulnDriver.Viragt"
    reference_sample = "58a74dceb2022cd8a358b92acd1b48a5e01c524c3b0195d7033e4bd55eff4495"
    severity         = 50
    arch_context     = "x86"
    scan_context     = "file"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 69 00 72 00 61 00 67 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
    $version            = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x0b][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

  condition:
    int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

