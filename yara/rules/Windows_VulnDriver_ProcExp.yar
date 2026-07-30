rule Windows_VulnDriver_ProcExp_aeb4e5c0 {
    meta:
        author = "Elastic Security"
        id = "aeb4e5c0-5ed5-4ecf-95a5-a741c105f02f"
        fingerprint = "b06d9e07aebfe4acadb717f7a8534feb6863b0649cd10fbbf9b53587a855ea01"
        creation_date = "2022-04-04"
        last_modified = "2022-10-26"
        description = "Name: procexp.Sys, Version: 16.65535.65535.65535"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\xff][\x00-\xff])([\x00-\x10][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xff][\x00-\xff])([\x00-\x0f][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xfe][\x00-\xff])([\x00-\x10][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xff][\x00-\xff])([\x00-\x10][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xfe][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_ProcExp_2284a052 {
    meta:
        author = "Elastic Security"
        id = "2284a052-97f7-4134-bfde-95e8deb4849f"
        fingerprint = "a1b157450bd3b0a6ccc6839b56d26aa1eec372f036dd3925fffeaf026154d2f0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 16.42.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "16a2e578bc8683f17a175480fea4f53c838cfae965f1d4caa47eaf9e0b3415c1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x29][\x00-\x00][\x10-\x10][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x2a-\x2a][\x00-\x00][\x10-\x10][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ProcExpDriver.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcExp_2845bebb {
    meta:
        author = "Elastic Security"
        id = "2845bebb-889a-4eb1-acdb-68270d63c6f4"
        fingerprint = "27e720d7807151a59cdb888021cd5c4ac68edfa84119e0e5a6bf9f7ac9062fc1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sysinternals, Version: <= 12.0.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "1b00d6e5d40b1b84ca63da0e99246574cdd2a533122bc83746f06c0d66e63a6e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 73 69 6E 74 65 72 6E 61 6C 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "procexp141.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcExp_682db69a {
    meta:
        author = "Elastic Security"
        id = "682db69a-46b7-4322-9a7b-bb70a6c5fa2e"
        fingerprint = "0b81a9297f84dd46e572e9b405c188769dbfa33cc4a01c75ea0d19b8c79f8c7e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sysinternals, Version: <= 11.30.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "30abc0cc700fdebc74e62d574addc08f6227f9c7177d9eaa8cbc37d5c017c9bb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 73 69 6E 74 65 72 6E 61 6C 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1d][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x1e-\x1e][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "procexp130.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcExp_b6006008 {
    meta:
        author = "Elastic Security"
        id = "b6006008-b8ec-4243-b99e-1c212f76ffb5"
        fingerprint = "84a54ddd949f67797c2a3ac7b2a9b46b35fb2f09d2bdd92d1114c55680e93bff"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sysinternals, Version: <= 15.0.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "3c7e5b25a33a7805c999d318a9523fcae46695a89f55bbdb8bb9087360323dfc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 73 69 6E 74 65 72 6E 61 6C 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ProcExpDriver.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcExp_e51390a6 {
    meta:
        author = "Elastic Security"
        id = "e51390a6-61b8-4ba6-ba2e-e0ea719527e4"
        fingerprint = "daf123844d81e3e9ba69790dcc58d280e19b6212027350546cea29ca52dd860b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sysinternals, Version: <= 11.40.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "3ff39728f1c11d1108f65ec5eb3d722fd1a1279c530d79712e0d32b34880baaa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 73 69 6E 74 65 72 6E 61 6C 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x27][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x28-\x28][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "procexp140.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcExp_cca50cbf {
    meta:
        author = "Elastic Security"
        id = "cca50cbf-0187-4268-8682-d57d1fe66660"
        fingerprint = "e6d9746200856467ad1ed538d47f941bb5d3ccfc8bf743398dba8fae628f3ebe"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 15.0.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "77950e2a40ac0447ae7ee1ee3ef1242ce22796a157074e6f04e345b1956e143c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ProcExpDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_ProcExp_84ab26d0 {
    meta:
        author = "Elastic Security"
        id = "84ab26d0-5ac6-4ec7-a4b8-aa36c0a9cd13"
        fingerprint = "3bf107b1fd285598218b139516598a16b04d55e4b4c11baa5873975c6eef8384"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Mark Russinovich, Version: <= 15.0.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "9d5ebd0f4585ec20a5fe3c5276df13ece5a2645d3d6f70cedcda979bd1248fc2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 72 6B 20 52 75 73 73 69 6E 6F 76 69 63 68 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ProcExpDriver.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcExp_b45cbab2 {
    meta:
        author = "Elastic Security"
        id = "b45cbab2-8ecf-47f6-8328-1fdef05a6396"
        fingerprint = "bfd5a757e9647b025570404eb6cfe45ff6eb29c02fa708bad8c6dc53e2076b4e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sysinternals, Version: <= 9.30.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "bced04bdefad6a08c763265d6993f07aa2feb57d33ed057f162a947cf0e6668f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 73 69 6E 74 65 72 6E 61 6C 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1d][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x1e-\x1e][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_ProcExp_5517e9fc {
    meta:
        author = "Elastic Security"
        id = "5517e9fc-e057-4715-badd-dc3f4e89a6d9"
        fingerprint = "6e796e7798138721142c53042a57beadc8b09387eb3f1a8c9aaf5b78a5932129"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Sysinternals, Version: <= 11.1.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "bdbceca41e576841cad2f2b38ee6dbf92fd77fbbfdfe6ecf99f0623d44ef182c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 79 73 69 6E 74 65 72 6E 61 6C 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "procexp111.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ProcExp_efe741bf {
    meta:
        author = "Elastic Security"
        id = "efe741bf-3e76-4f29-9113-9e95e5c1fd2a"
        fingerprint = "3d09b21197f327a720226c06a91f3f2bf29e159ba7dfc65ba94baea6f16e4e9c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Corporation, Version: <= 15.0.0.0"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "e07211224b02aaf68a5e4b73fc1049376623793509d9581cdaee9e601020af06"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ProcExpDriver.pdb"
        $str2 = "Process Explorer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

