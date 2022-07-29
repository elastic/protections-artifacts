rule Multi_Trojan_Bishopsliver_42298c4a {
    meta:
        id = "42298c4a-fcea-4c5a-b213-32db00e4eb5a"
        fingerprint = "0734b090ea10abedef4d9ed48d45c834dd5cf8e424886a5be98e484f69c5e12a"
        creation_date = "2021-10-20"
        last_modified = "2022-01-14"
        threat_name = "Multi.Trojan.Bishopsliver"
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

