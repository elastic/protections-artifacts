rule Windows_Hacktool_ChromElevator_72810406 {
    meta:
        author = "Elastic Security"
        id = "72810406-349b-4f14-97aa-a89bb839789d"
        fingerprint = "b2aef6fed1007c19ef38afaf6c199cde323f7dd7fe80f7cddbe6114782768e43"
        creation_date = "2026-08-11"
        last_modified = "2026-09-09"
        threat_name = "Windows.Hacktool.ChromElevator"
        reference_sample = "55cce9b11e7540e1f5452621ebf8383ba34a2b8d1641992fc375d03c50bfda1c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "SELECT guid, value_encrypted FROM" ascii fullword
        $b = "SELECT service, encrypted_token FROM" ascii fullword
        $c = "Extracting comprehensive fingerprint..." ascii fullword
        $d = "No browser processes found" ascii fullword
        $e = "Warning: Syscall initialization failed." ascii fullword
    condition:
        3 of them
}

