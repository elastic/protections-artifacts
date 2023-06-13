rule Windows_Trojan_DownTown_901c4fdd {
    meta:
        author = "Elastic Security"
        id = "901c4fdd-858c-4ad8-be12-f88799d591b9"
        fingerprint = "1ef6dfd9be1e6fa2d1c6b5ce32ad13252f5becf709493a7cceff3519750e0b1e"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.DownTown"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "SendFileBuffer error -1 !!!" fullword
        $a2 = "ScheduledDownloadTasks CODE_FILE_VIEW " fullword
        $a3 = "ExplorerManagerC.dll" fullword
    condition:
        3 of them
}

