rule Windows_Trojan_Generic_a681f24a {
    meta:
        author = "Elastic Security"
        id = "a681f24a-7054-4525-bcf8-3ee64a1d8413"
        fingerprint = "6323ed5b60e728297de19c878cd96b429bfd6d82157b4cf3475f3a3123921ae0"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a796f316b1ed7fa809d9ad5e9b25bd780db76001345ea83f5035a33618f927fa"
        severity = 25
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "_kasssperskdy" wide fullword
        $b = "[Time:]%d-%d-%d %d:%d:%d" wide fullword
        $c = "{SDTB8HQ9-96HV-S78H-Z3GI-J7UCTY784HHC}" wide fullword
    condition:
        2 of them
}

rule Windows_Trojan_Generic_ae824b13 : ref1296 {
    meta:
        author = "Elastic Security"
        id = "ae824b13-eaae-49e6-a965-ff10379f3c41"
        fingerprint = "8658996385aac060ebe9eab45bbea8b05b9008926bb3085e5589784473bc3086"
        creation_date = "2022-02-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 31 31 34 2E 31 31 34 2E 31 31 34 2E 31 31 34 }
        $a2 = { 69 6E 66 6F 40 63 69 61 2E 6F 72 67 30 }
        $a3 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 30 2E 30 2E 32 36 36 31 2E 39 34 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
        $a4 = { 75 73 65 72 25 33 64 61 64 6D 69 6E 25 32 36 70 61 73 73 77 6F 72 64 25 33 64 64 65 66 61 75 6C 74 25 34 30 72 6F 6F 74 }
    condition:
        3 of them
}

rule Windows_Trojan_Generic_eb47e754 : ref1296 {
    meta:
        author = "Elastic Security"
        id = "eb47e754-9b4d-45e7-b76c-027d03326c6c"
        fingerprint = "b71d13a34e5f791612ed414b8b0e993b1f476a8398a1b0be39046914ac5ac21d"
        creation_date = "2022-02-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 41 20 61 74 20 4C 20 25 64 }
        $a2 = { 74 63 70 69 70 5F 74 68 72 65 61 64 }
        $a3 = { 32 30 38 2E 36 37 2E 32 32 32 2E 32 32 32 }
        $a4 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 37 2E 30 2E 32 39 38 37 2E 31 33 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
    condition:
        3 of them
}

rule Windows_Trojan_Generic_c7fd8d38 {
    meta:
        author = "Elastic Security"
        id = "c7fd8d38-eaba-424d-b91a-098c439dab6b"
        fingerprint = "dc14cd519b3bbad7c2e655180a584db0a4e2ad4eea073a52c94b0a88152b37ba"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a1702ec12c2bf4a52e11fbdab6156358084ad2c662c8b3691918ef7eabacde96"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PCREDENTIAL" ascii fullword
        $a2 = "gHotkey" ascii fullword
        $a3 = "EFORMATEX" ascii fullword
        $a4 = "ZLibEx" ascii fullword
        $a5 = "9Root!" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Generic_a160ca52 {
    meta:
        author = "Elastic Security"
        id = "a160ca52-8911-4649-a1fa-ac8f6f75e18d"
        fingerprint = "06eca9064ca27784b61994844850f05c47c07ba6c4242a2572d6d0c484a920f0"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "650bf19e73ac2d9ebbf62f15eeb603c2b4a6a65432c70b87edc429165d6706f3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 1C 85 C9 74 02 8B 09 8D 41 FF 89 45 F0 89 55 EC 8B 55 EC 8B }
    condition:
        all of them
}

rule Windows_Trojan_Generic_bbe6c282 {
    meta:
        author = "Elastic Security"
        id = "bbe6c282-e92d-4021-bdaf-189337e4abf0"
        fingerprint = "e004d77440a86c23f23086e1ada6d1453178b9c2292782c1c88a7b14151c10fe"
        creation_date = "2022-03-02"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 D1 1C A5 03 08 08 00 8A 5C 01 08 08 00 8A 58 01 2E 54 FF }
    condition:
        all of them
}

rule Windows_Trojan_Generic_889b1248 {
    meta:
        author = "Elastic Security"
        id = "889b1248-a694-4c9b-8792-c04e582e814c"
        fingerprint = "a5e0c2bbd6a297c01f31eccabcbe356730f50f074587f679da6caeca99e54bc1"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a48d57a139c7e3efa0c47f8699e2cf6159dc8cdd823b16ce36257eb8c9d14d53"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BELARUS-VIRUS-MAKER" ascii fullword
        $a2 = "C:\\windows\\temp\\" ascii fullword
        $a3 = "~c~a~n~n~a~b~i~s~~i~s~~n~o~t~~a~~d~r~u~g~" ascii fullword
        $a4 = "untInfector" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Generic_02a87a20 {
    meta:
        author = "Elastic Security"
        id = "02a87a20-a5b4-44c6-addc-c70b327d7b2c"
        fingerprint = "fb25a522888efa729ee6d43a3eec7ade3d08dba394f3592d1c3382a5f7a813c8"
        creation_date = "2022-03-04"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 3C 8B C2 2B C1 83 F8 01 72 3A 8D 41 01 83 FA 08 89 44 24 38 8D 44 }
    condition:
        all of them
}

