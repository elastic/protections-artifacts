rule Windows_VulnDriver_Avast_bdbb7f30 {
    meta:
        author = "Elastic Security"
        id = "bdbb7f30-4513-47eb-9622-2bf839d735bf"
        fingerprint = "6b1be2a00b2e3f32df8c8aa70bbd7594ac478ef4fdb45ef9d428814c1e2030ae"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software a.s., Version: <= 10.0.0.1126"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "1072beb3ff6b191b3df1a339e3a8c87a8dc5eae727f2b993ea51b448e837636a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 61 2E 73 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 67 00 69 00 6F 00 64 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x65][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x66-\x66][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "ngiodriver_x86.pdb"
        $str2 = "avast! NG" wide
        $str3 = "avast! NG setup helper driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_cc54c33c {
    meta:
        author = "Elastic Security"
        id = "cc54c33c-a644-4df8-9a4c-bee0ffef7ccf"
        fingerprint = "f135f5183d0e304ec1ca651422e7cda3fc77c7ab1cfb59c3644d0c92e146c10b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Avast Software s.r.o., Version: <= 20.8.137.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "17687cba00ec2c9036dd3cb5430aa1f4851e64990dafb4c8f06d88de5283d6ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 76 61 73 74 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x88][\x00-\x00]|[\x08-\x08][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\x89-\x89][\x00-\x00])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast Anti Rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_2f69bce9 {
    meta:
        author = "Elastic Security"
        id = "2f69bce9-86ca-483e-bf7d-fb143572cd81"
        fingerprint = "033083a27ea0bd7d491a8370196e61b413398f752e2ce2cc0706e40588cd01ed"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Netherlands B.V., Version: <= 18.5.3931.361"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "1dccd1e13da17bd541a66b48d62e914df390818c15f5f599c636d42c05996ace"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 4E 65 74 68 65 72 6C 61 6E 64 73 20 42 2E 56 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 53 00 50 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x5a][\x0f-\x0f])|[\x05-\x05][\x00-\x00][\x12-\x12][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x68][\x01-\x01])[\x5b-\x5b][\x0f-\x0f]|[\x05-\x05][\x00-\x00][\x12-\x12][\x00-\x00][\x69-\x69][\x01-\x01][\x5b-\x5b][\x0f-\x0f])/
        $str1 = "aswSP.pdb"
        $str2 = "IOCTL_ASWSP_START_REQUEST_AND_SET_RESULTS"
        $str3 = "AVG Internet Security System " wide
        $str4 = "AVG self protection module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Avast_556e7746 {
    meta:
        author = "Elastic Security"
        id = "556e7746-71f0-46ef-8bf3-e4b0b5ee92a0"
        fingerprint = "785ba92ff13b0649dad55843bbd3d50ffda30da0ee197318fb1081eeda4ebb9b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Netherlands B.V., Version: <= 18.3.3860.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "2594b3ef3675ca3a7b465b8ed4962e3251364bab13b12af00ebba7fa2211abb2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 4E 65 74 68 65 72 6C 61 6E 64 73 20 42 2E 56 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x13][\x0f-\x0f])|[\x03-\x03][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\x00][\x00-\x00][\x14-\x14][\x0f-\x0f])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_5cd9e6b9 {
    meta:
        author = "Elastic Security"
        id = "5cd9e6b9-ccdc-416d-a810-8fa0f0cdee67"
        fingerprint = "c7106958c601b56e51d76adc828de3b8c89d432b3e0924823bc379abe9b3f2e3"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Technologies USA, LLC, Version: <= 20.10.171.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "2ce81759bfa236913bbbb9b2cbc093140b099486fd002910b18e2c6e31fdc4f1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 55 53 41 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xaa][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\xab-\xab][\x00-\x00])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG Anti Rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_92cd6218 {
    meta:
        author = "Elastic Security"
        id = "92cd6218-f78f-45ba-b29b-87ab3678e007"
        fingerprint = "2b98b4f2f9a448d8ecf936f702d59de5a420e12843d788277afd19f14bbac559"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software, Version: <= 8.0.1497.376"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 56 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x04]|[\x00-\xd8][\x05-\x05])|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x77][\x01-\x01])[\xd9-\xd9][\x05-\x05]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x78-\x78][\x01-\x01][\xd9-\xd9][\x05-\x05])/
        $str1 = "aswVmm.pdb"
        $str2 = "avast! Antivirus" wide
        $str3 = "avast! VM Monitor" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_46028c76 {
    meta:
        author = "Elastic Security"
        id = "46028c76-cee6-44d7-833d-6935e08970c8"
        fingerprint = "7dda88befffd92f07c2760b3d7ddd762493365d34848d62574ce8d9661588943"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software a.s., Version: <= 11.0.0.362"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "5fae7e491b0d919f0b551e15e0942ac7772f2889722684aea32cff369e975879"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 61 2E 73 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 67 00 69 00 6F 00 64 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x69][\x01-\x01])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00][\x6a-\x6a][\x01-\x01][\x00-\x00][\x00-\x00])/
        $str1 = "ngiodriver_x86.pdb"
        $str2 = "Avast NG" wide
        $str3 = "avast! NG setup helper driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_5af8af76 {
    meta:
        author = "Elastic Security"
        id = "5af8af76-02b7-4f28-a165-84791bb6a967"
        fingerprint = "0a6b6904f34df86faf6bd787b7da24048c493116738234019abe4c874b8b9d34"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Avast Software s.r.o., Version: <= 20.4.83.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "7ad0ab23023bc500c3b46f414a8b363c5f8700861bc4745cecc14dd34bcee9ed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 76 61 73 74 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x52][\x00-\x00]|[\x04-\x04][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\x53-\x53][\x00-\x00])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast Anti Rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_447cc9f0 {
    meta:
        author = "Elastic Security"
        id = "447cc9f0-ab72-4ec6-9306-b19ab308b243"
        fingerprint = "4d6685f33763c44f2f34f25aa15094423cc8e379a7d20d7b2e4f70173958d54b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Technologies CZ, s.r.o., Version: <= 17.9.3761.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "7d43769b353d63093228a59eb19bba87ce6b552d7e1a99bf34a54eee641aa0ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 5A 2C 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x10][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x11-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x11-\x11][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0d]|[\x00-\xb0][\x0e-\x0e])|[\x09-\x09][\x00-\x00][\x11-\x11][\x00-\x00][\x00-\x00][\x00-\x00][\xb1-\xb1][\x0e-\x0e])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_804c74f8 {
    meta:
        author = "Elastic Security"
        id = "804c74f8-6445-4ef2-92f1-6f178f02d10b"
        fingerprint = "af35836d90436c67b40e17d14d3599a7f45d93dff133f9b809c5e03de99705bc"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Technologies USA, Inc., Version: <= 19.7.4246.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "8cfd5b2102fbc77018c7fe6019ec15f07da497f6d73c32a31f4ba07e67ec85d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 55 53 41 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0f]|[\x00-\x95][\x10-\x10])|[\x07-\x07][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\x00][\x00-\x00][\x96-\x96][\x10-\x10])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_77ea1c4e {
    meta:
        author = "Elastic Security"
        id = "77ea1c4e-99d7-4595-b01f-73ae62ccdc14"
        fingerprint = "f63847f5aeb4d1f438138e1c5eee7397a6758e36a621eed9329bfce4bb8af1ba"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Technologies USA, Inc., Version: <= 19.2.4181.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "a2f45d95d54f4e110b577e621fefa0483fa0e3dcca14c500c298fb9209e491c1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 55 53 41 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0f]|[\x00-\x54][\x10-\x10])|[\x02-\x02][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\x00][\x00-\x00][\x55-\x55][\x10-\x10])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_0dde1c4e {
    meta:
        author = "Elastic Security"
        id = "0dde1c4e-8b36-4fc9-9c9e-851809f5cba6"
        fingerprint = "1e53d5537655447abb4cf1af5a03a29dfed880dd5c012a6734a1ab8903f73d47"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software s.r.o., Version: <= 18.6.3979.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "d5c4ff35eaa74ccdb80c7197d3d113c9cd38561070f2aa69c0affe8ed84a77c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x8a][\x0f-\x0f])|[\x06-\x06][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\x00][\x00-\x00][\x8b-\x8b][\x0f-\x0f])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_dac4c6be {
    meta:
        author = "Elastic Security"
        id = "dac4c6be-eaa6-435a-9028-589abef3c105"
        fingerprint = "a497f7c04c6b573ae2505b95dfb3bb5beebb073375a3ddc87daff4c435c45b4c"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software s.r.o., Version: <= 19.7.4246.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "dcb815eb8e9016608d0d917101b6af8c84b96fb709dc0344bceed02cbc4ed258"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0f]|[\x00-\x95][\x10-\x10])|[\x07-\x07][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\x00][\x00-\x00][\x96-\x96][\x10-\x10])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Avast_c4f8f98f {
    meta:
        author = "Elastic Security"
        id = "c4f8f98f-36d0-404c-b740-f817b6e0eb7a"
        fingerprint = "0f79ad41d649478b0d7ae3762d07b01ada1d3ff2e473f5b6dd973432897b6a9f"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software a.s., Version: <= 10.0.0.1126"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "e8eb1c821dbf56bde05c0c49f6d560021628df89c29192058ce68907e7048994"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 61 2E 73 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 67 00 69 00 6F 00 64 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x65][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x66-\x66][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "ngiodriver_x64.pdb"
        $str2 = "avast! NG" wide
        $str3 = "avast! NG setup helper driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

