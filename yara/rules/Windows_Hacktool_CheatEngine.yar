rule Windows_Hacktool_CheatEngine_fedac96d {
    meta:
        author = "Elastic Security"
        id = "fedac96d-4c23-4c8d-8476-4c89fd610441"
        fingerprint = "7cc11532e345512f3f3ec587888826017c6f79425f3fa403d291a8f565c1d142"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: Cheat Engine"
        threat_name = "Windows.Hacktool.CheatEngine"
        reference_sample = "b20b339a7b61dc7dbc9a36c45492ba9654a8b8a7c8cbc202ed1dfed427cfd799"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 61 74 20 45 6E 67 69 6E 65 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name in (filesize - 50KB .. filesize)
}

