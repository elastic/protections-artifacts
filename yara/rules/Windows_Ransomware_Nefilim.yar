rule Windows_Ransomware_Nefilim_3969d6a7 {
    meta:
        author = "Elastic Security"
        id = "3969d6a7-4601-4bf1-8434-a0f48e93c7c4"
        fingerprint = "734c8802f201052c2c29c6905a2a222eec592f913a3b65e0daf2af2e53ea3eb0"
        creation_date = "2026-07-08"
        last_modified = "2026-07-15"
        threat_name = "Windows.Ransomware.Nefilim"
        reference_sample = "0bafde9b22d7147de8fdb852bcd529b1730acddc9eb71316b66c180106f777f5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "NEF1LIM"
        $b = "-DECRYPT.txt"
        $c = "main.BytesToPublicKey"
    condition:
        all of them
}

rule Windows_Ransomware_Nefilim_b0a7934b {
    meta:
        author = "Elastic Security"
        id = "b0a7934b-ab42-4bca-b8e3-505371e7c509"
        fingerprint = "a851bce75757d3c6a18534284759c8a35486511c8c69dffbe7b62f9d68940d54"
        creation_date = "2026-07-08"
        last_modified = "2026-07-15"
        threat_name = "Windows.Ransomware.Nefilim"
        reference_sample = "5826849eb9a8b3a1910c048a760b7784c1043a488afc9b588a2151b036987edf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = ".NEFILIM" wide fullword
        $b = "NEFILIM-DECRYPT.txt" wide fullword
        $c = "oh how i did it??? bypass sofos hah" ascii fullword
        $d = "timeout /t 3 /nobreak && del" wide fullword
        $e = "ya chubstvuu bol' gde-to v grude, i moi rani v serdce ne zalechit'" ascii fullword
    condition:
        3 of them
}

