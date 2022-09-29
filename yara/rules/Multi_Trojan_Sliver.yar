rule Multi_Trojan_Sliver_42298c4a {
    meta:
        author = "Elastic Security"
        id = "42298c4a-fcea-4c5a-b213-32db00e4eb5a"
        fingerprint = "0734b090ea10abedef4d9ed48d45c834dd5cf8e424886a5be98e484f69c5e12a"
        creation_date = "2021-10-20"
        last_modified = "2022-01-14"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "3b45aae401ac64c055982b5f3782a3c4c892bdb9f9a5531657d50c27497c8007"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = ").RequestResend"
        $a2 = ").GetPrivInfo"
        $a3 = ").GetReconnectIntervalSeconds"
        $a4 = ").GetPivotID"
        $a5 = "name=PrivInfo"
        $a6 = "name=ReconnectIntervalSeconds"
        $a7 = "name=PivotID"
    condition:
        2 of them
}

rule Multi_Trojan_Sliver_3bde542d {
    meta:
        author = "Elastic Security"
        id = "3bde542d-df52-4f05-84ff-de67e90592a9"
        fingerprint = "e52e39644274e3077769da4d04488963c85a0b691dc9973ad12d51eb34ba388b"
        creation_date = "2022-08-31"
        last_modified = "2022-09-29"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "05461e1c2a2e581a7c30e14d04bd3d09670e281f9f7c60f4169e9614d22ce1b3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb" ascii fullword
        $b1 = "InvokeSpawnDllReq" ascii fullword
        $b2 = "NetstatReq" ascii fullword
        $b3 = "HTTPSessionInit" ascii fullword
        $b4 = "ScreenshotReq" ascii fullword
        $b5 = "RegistryReadReq" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

