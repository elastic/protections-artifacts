rule Multi_Trojan_Gosar_31dba745 {
  meta:
    author           = "Elastic Security"
    id               = "31dba745-8079-4161-9299-84a4c33b95c8"
    fingerprint      = "87e44b3050eb33edb24ad8aa8923ed91124f2e92e4eae42e94decefc49ccbf4c"
    creation_date    = "2024-11-05"
    last_modified    = "2024-12-04"
    threat_name      = "Multi.Trojan.Gosar"
    reference_sample = "4caf4b280e61745ce53f96f48a74dea3b69df299c3b9de78ba4731b83c76c334"
    severity         = 100
    arch_context     = "x86, arm64"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "multi"

  strings:
    $a1 = "GetRecoverAccounts"
    $a2 = "GetIsFirstScreen"
    $a3 = "DoWebcamStop"
    $a4 = "DoAskElevate"
    $a5 = "vibrant/proto/pb"
    $a6 = "vibrant/network/sender"
    $a7 = "vibrant/pkg/helpers"

  condition:
    3 of them
}

