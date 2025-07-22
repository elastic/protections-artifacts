rule MacOS_Cryptominer_Generic_d3f68e29 {
  meta:
    author           = "Elastic Security"
    id               = "d3f68e29-830d-4d40-a285-ac29aed732fa"
    fingerprint      = "733dadf5a09f4972629f331682fca167ebf9a438004cb686d032f69e32971bd4"
    creation_date    = "2021-09-30"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Cryptominer.Generic"
    reference_sample = "d9c78c822dfd29a1d9b1909bf95cab2a9550903e8f5f178edeb7a5a80129fbdb"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a1 = "command line argument. See 'ethminer -H misc' for details." ascii fullword
    $a2 = "Ethminer - GPU ethash miner" ascii fullword
    $a3 = "StratumClient"

  condition:
    all of them
}

rule MacOS_Cryptominer_Generic_365ecbb9 {
  meta:
    author           = "Elastic Security"
    id               = "365ecbb9-586e-4962-a5a8-05e871f54eff"
    fingerprint      = "5ff82ab60f8d028c9e4d3dd95609f92cfec5f465c721d96947b490691d325484"
    creation_date    = "2021-09-30"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Cryptominer.Generic"
    reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a = "Unknown network specified "

  condition:
    all of them
}

rule MacOS_Cryptominer_Generic_4e7d4488 {
  meta:
    author           = "Elastic Security"
    id               = "4e7d4488-2e0c-4c74-84f9-00da103e162a"
    fingerprint      = "4e7f22e8084734aeded9b1202c30e6a170a6a38f2e486098b4027e239ffed2f6"
    creation_date    = "2021-09-30"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Cryptominer.Generic"
    reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a = "is field to show number of"

  condition:
    all of them
}

