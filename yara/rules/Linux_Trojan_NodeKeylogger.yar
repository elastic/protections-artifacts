rule Linux_Trojan_NodeKeylogger_092fa138 {
    meta:
        author = "Elastic Security"
        id = "092fa138-8bb4-4f1b-8c8f-5cf37d970d99"
        fingerprint = "5049bcb54f5fb65d12a643dab0a8989b6b80322ab1b52b9b939affdf7f2984b0"
        creation_date = "2026-03-25"
        last_modified = "2026-07-07"
        threat_name = "Linux.Trojan.NodeKeylogger"
        reference_sample = "6e09249262d9a605180dfbd0939379bbf9f37db0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a0 = "KEYBOARD" fullword
        $a1 = "MOUSE" fullword
        $a2 = "DOWN" fullword
        $b = { 48 8B ?? ?? FF FF FF 8B 40 24 83 F8 0D 74 ?? 48 8B ?? ?? FF FF FF 8B 40 24 83 F8 0F 75 }
    condition:
        all of them
}

