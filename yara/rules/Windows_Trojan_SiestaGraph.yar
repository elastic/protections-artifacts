rule Windows_Trojan_SiestaGraph_8c36ddc1 {
    meta:
        author = "Elastic Security"
        id = "8c36ddc1-c7fa-4c25-a05c-59c29e4e7c31"
        fingerprint = "a76d2b45261da65215797a4792a3aae5051d88ba15d01b24487c83d6a38b9ff7"
        creation_date = "2022-12-14"
        last_modified = "2022-12-15"
        threat_name = "Windows.Trojan.SiestaGraph"
        reference_sample = "50c2f1bb99d742d8ae0ad7c049362b0e62d2d219b610dcf25ba50c303ccfef54"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "downloadAsync" ascii nocase fullword
        $a2 = "UploadxAsync" ascii nocase fullword
        $a3 = "GetAllDriveRootChildren" ascii fullword
        $a4 = "GetDriveRoot" ascii fullword
        $a5 = "sendsession" wide fullword
        $b1 = "ListDrives" wide fullword
        $b2 = "Del OK" wide fullword
        $b3 = "createEmailDraft" ascii fullword
        $b4 = "delMail" ascii fullword
    condition:
        all of ($a*) and 2 of ($b*)
}

