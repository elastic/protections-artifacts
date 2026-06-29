rule Windows_VulnDriver_Asrock_986d2d3c {
    meta:
        author = "Elastic Security"
        id = "986d2d3c-96d1-4c74-a594-51c6df3b2896"
        fingerprint = "17a021c4130a41ca6714f2dd7f33c100ba61d6d2d4098a858f917ab49894b05b"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\AsrDrv106.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_Asrock_cdf192f9 {
    meta:
        author = "Elastic Security"
        id = "cdf192f9-c62f-4e00-b6a9-df85d10fee99"
        fingerprint = "f27c61c67b51ab88994742849dcd1311064ef0cacddb57503336d08f45059060"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\AsrDrv103.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_Asrock_0eca57dc {
    meta:
        author = "Elastic Security"
        id = "0eca57dc-3800-4b0f-99dd-151fcac82136"
        fingerprint = "6c73b37f5e749161b4fb2f076e82ceb02345894b5db8e1a187019b54e3d1a154"
        creation_date = "2023-07-20"
        last_modified = "2023-07-20"
        description = "Name: AsrSetupDrv103.sys, Version: 1.00.00.0000 built by: WinDDK"
        threat_name = "Windows.Vulndriver.Asrock"
        reference_sample = "9d9346e6f46f831e263385a9bd32428e01919cca26a035bbb8e9cb00bf410bc3"
        reference_sample = "a0728184caead84f2e88777d833765f2d8af6a20aad77b426e07e76ef91f5c3f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 [1-8] 41 00 73 00 72 00 53 00 65 00 74 00 75 00 70 00 44 00 72 00 76 00 31 00 30 00 33 00 2E 00 73 00 79 00 73 }
        $file_version = { 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E [1-8] 31 00 2E 00 30 00 30 00 2E 00 30 00 30 00 2E 00 30 00 30 00 30 00 30 00 20 00 62 00 75 00 69 00 6C 00 74 00 20 00 62 00 79 00 3A 00 20 00 57 00 69 00 6E 00 44 00 44 00 4B }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $file_version
}

rule Windows_VulnDriver_Asrock_1fbc5298 {
    meta:
        author = "Elastic Security"
        id = "1fbc5298-b1d9-4481-b803-e14c8b23654c"
        fingerprint = "eba54c842bf845ffe55d3eee7744d778e26f9430120ec00792c01c3b8d8a94d7"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "04cc7df4077e36199b04afa39204c8f568f7f66f045e73010fb9b7685324442f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 43 00 44 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrCDDrv.pdb"
        $str2 = "ASRock Setup utility" wide
        $str3 = "ASRock Setup Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Asrock_14013bcc {
    meta:
        author = "Elastic Security"
        id = "14013bcc-5032-4c04-af9d-e7087c7e452b"
        fingerprint = "71e29e275944b2041f7bf35c6fccd2c49a65461497682df8e011943e68091011"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "0aafa9f47acf69d46c9542985994ff5321f00842a28df2396d4a3076776a83cb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrRapidStartDrv.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_9e4e8b75 {
    meta:
        author = "Elastic Security"
        id = "9e4e8b75-6f5d-4fc4-bd21-6ccf57e72812"
        fingerprint = "a1aea70a25267a840b7318221007d2a5afca7957f0e8ccd40aee2399dcc092ee"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK INC., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "12177d777345f60a579e7bd8f0df95296af6e293e5560ee544fcced99a5db0df"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv107n.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_f722c968 {
    meta:
        author = "Elastic Security"
        id = "f722c968-c7ab-472d-ba03-535bb733b169"
        fingerprint = "fc0c509985bb1164826f85d009958e6e0f1799e90312f3f84a3c89d7a54341e8"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK INC., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "14c5576eda5a28d476a93c9cdb91236f18573dbd0578ac2bb183dfd115f4a166"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv106n.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_a776029b {
    meta:
        author = "Elastic Security"
        id = "a776029b-ab61-4ce4-8bb4-c285bc79ed29"
        fingerprint = "82b73fe1bcd357b190e19f654eb5338d22373fc2275b3c82a255a3c3ccb780ac"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "1e0eb0811a7cf1bdaf29d3d2cab373ca51eb8d8b58889ab7728e2d3aed244abe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RwDrv.pdb"
        $str2 = "RwDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_59160b25 {
    meta:
        author = "Elastic Security"
        id = "59160b25-faf9-49c2-8d4e-e7f0a0146eb2"
        fingerprint = "001251df4752e6c2a89e4e588990615589fa9ae9a098a7481e5be0b6c16a8a05"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "2470fd1b733314c9b0afa19fd39c5d19aa1b36db598b5ebbe93445caa545da5f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AxtuDrv.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_dbc772f6 {
    meta:
        author = "Elastic Security"
        id = "dbc772f6-03c3-4bbc-ac26-3e87670c879c"
        fingerprint = "f70ada632b72e479bbc0e5677178f2d06bd6f0aeee0c4596a96019c8f94f6107"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "2a652de6b680d5ad92376ad323021850dab2c653abf06edf26120f7714b8e08a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrIbDrv.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_56c671c8 {
    meta:
        author = "Elastic Security"
        id = "56c671c8-5594-4d73-956d-01fb86102289"
        fingerprint = "51b5ea4857f32b2f19047e7470dc26e75bcd66851bd00a27b00c7dedec2153e0"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "2aa1b08f47fbb1e2bd2e4a492f5d616968e703e1359a921f62b38b8e4662f0c4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 41 00 75 00 74 00 6F 00 43 00 68 00 6B 00 55 00 70 00 64 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrAutoChkUpdDrv.pdb"
        $str2 = "AsrAutoChkUpdDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_e462900b {
    meta:
        author = "Elastic Security"
        id = "e462900b-4531-43cc-a6c3-f56ee56d3221"
        fingerprint = "09cf8cda51dbfd51f5b0f1232c6c5b2228f474a1fc1ca024878f0fb65b5b06f0"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "3384f4a892f7aa72c43280ff682d85c8e3936f37a68d978d307a9461149192de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrUrSet.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_7c90b972 {
    meta:
        author = "Elastic Security"
        id = "7c90b972-6631-42c4-bd0a-6cf8e838349f"
        fingerprint = "d1b551fbd0c10f5512782797c9043601a8524538db1a7bac952590a49b1950ce"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC., Version: <= 1.2.28.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "383df3b803ea69e16de314c82c2099283e746a6865cc4488ac927510ab5ada9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x1b][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x1c-\x1c][\x00-\x00])/
        $str1 = "AsIO3_64.sys.pdb"
        $str2 = "AsIO3 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_95747916 {
    meta:
        author = "Elastic Security"
        id = "95747916-a09d-401a-917b-90dd3e9786bd"
        fingerprint = "7f3326ee7398e152eaa73677274de07e11630bb57a252aeb558254c4d900a8e3"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "47f08f7d30d824a8f4bb8a98916401a37c0fd8502db308aba91fe3112b892dcc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrSmartConnectDrv.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_1abde0ad {
    meta:
        author = "Elastic Security"
        id = "1abde0ad-5f8e-4ae8-9aeb-6a937da2f284"
        fingerprint = "c89e85dfd427885aac16ffacf340daf0c2ce625ab2944e06afc2ee598fe0b117"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "4ae42c1f11a98dee07a0d7199f611699511f1fb95120fabc4c3c349c485467fe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 41 00 75 00 74 00 6F 00 43 00 68 00 6B 00 55 00 70 00 64 00 44 00 72 00 76 00 5F 00 31 00 5F 00 30 00 5F 00 33 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrAutoChkUpdDrv_1_0_32.pdb"
        $str2 = "AsrAutoChkUpdDrv_1_0_32 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_f1c71792 {
    meta:
        author = "Elastic Security"
        id = "f1c71792-0e75-4b49-bbcb-f67d7f462461"
        fingerprint = "830edaa9a4709ebc7896b89c592c3bb5265d521cfec96e2bfe7eb79a839adcdb"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "4b2b3bd860bb6c97cc39689a6faade6321bc760ce6b67c14ce77586ae7d89884"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrOcDrv.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_7dd0b19a {
    meta:
        author = "Elastic Security"
        id = "7dd0b19a-6c81-4341-94b9-3cda425afbd5"
        fingerprint = "8b91ee50dbe5a82b0ab4824f745a9c663fa52f72b972471f7d82b32e55acbe42"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "4bf974f5d3489638a48ee508b4a8cfa0f0262909778ccdd2e871172b71654d89"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv104n.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_911b5331 {
    meta:
        author = "Elastic Security"
        id = "911b5331-b7d9-453b-bbb7-3db98a28cf9b"
        fingerprint = "68e4ddcb49cb8a439914c8cf67517eba311deafd6b1238f543f7abf04601506c"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: AsrDrv.sys, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "4d03a01257e156a3a018230059052791c3cde556e5cec7a4dd2f55f65c06e146"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv103.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_fc9efe77 {
    meta:
        author = "Elastic Security"
        id = "fc9efe77-0dfe-4423-9a5c-c905317a6d87"
        fingerprint = "630d477181905cd21d221dd55bbd3499237e91157558c6b38f1a6bafa1d18785"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "5f9c9816eba11c3505990fff3b235636072ae3319fdc644d455ca51cb17914b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RWDRV.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_58edef45 {
    meta:
        author = "Elastic Security"
        id = "58edef45-bb77-48eb-a91a-c9a7ecd7ada2"
        fingerprint = "c2cf09edceaa579f7a1bb7d09e5a7548e080ea58cbe122f64429e8e02e0f854c"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "6ed35f310c96920a271c59a097b382da07856e40179c2a4239f8daa04eef38e7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv104.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_769874cd {
    meta:
        author = "Elastic Security"
        id = "769874cd-2c8d-41bd-b003-f01d43874d05"
        fingerprint = "eaec2d980037abda3d43da3af6b8dd52a6f15b9e0a2233d07350f7797ce03d74"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "950a4c0c772021cee26011a92194f0e58d61588f77f2873aa0599dff52a160c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrOmgDrv.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_7be9400c {
    meta:
        author = "Elastic Security"
        id = "7be9400c-f683-48a8-bd20-f1edca647d09"
        fingerprint = "2a0de573af18a04f41fe2fbbf63c0606a033e3e2cebd8b69c795ca0632680e8a"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK INC., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "9d9346e6f46f831e263385a9bd32428e01919cca26a035bbb8e9cb00bf410bc3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 53 00 65 00 74 00 75 00 70 00 44 00 72 00 76 00 31 00 30 00 33 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrSetupDrv103.pdb"
        $str2 = "AsrSetupDrv103 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_0880ec70 {
    meta:
        author = "Elastic Security"
        id = "0880ec70-dee3-4551-a620-51dffc05ef43"
        fingerprint = "326349c67ea0d91fd50a9ad36855cd07c27890e9703cdff19691aeccf82cfb18"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "a108cfc475504fd4091bf4425167c4f5adda727b0e475c31ee2335297edc4cdc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 53 00 65 00 74 00 75 00 70 00 44 00 72 00 76 00 33 00 5F 00 30 00 5F 00 33 00 38 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrSetupDrv3_0_38.pdb"
        $str2 = "AsrSetupDrv3_0_38 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_92946c17 {
    meta:
        author = "Elastic Security"
        id = "92946c17-22d3-44d6-bd32-d7a4349166ba"
        fingerprint = "4d74c50be01fc9a25a9befb0556f8b1b3feb1ffa0f0b6608c36c9a34f3475361"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "a7c2e7910942dd5e43e2f4eb159bcd2b4e71366e34a68109548b9fb12ac0f7cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv102.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_3cd3026a {
    meta:
        author = "Elastic Security"
        id = "3cd3026a-3d47-4110-94b7-7f6e0d17ef4f"
        fingerprint = "f6b16eb344c088f30bc0701f7012f2ca435c2a01890fa84c50dc2003b9cf6271"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK INC., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "bc3f73f643b8d3108661fe1ff6a816cbc4482a056ef90c29042b448a45077bd3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv105.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_28bad5d0 {
    meta:
        author = "Elastic Security"
        id = "28bad5d0-39db-4f3a-8dc2-1ca64999939c"
        fingerprint = "b4d97d05f8799e7609a28bebe1422873a93d56934d0ebd32126d5034ebbecc6a"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK INC., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "be131e30464c7be03bd2d16f99ea2b04c106b482cc5c52be659e4c0301206348"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv107.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_d6ca6130 {
    meta:
        author = "Elastic Security"
        id = "d6ca6130-3df2-4324-9f78-84ec274e28c1"
        fingerprint = "b8dd7425e93cdf5ae01319dab4278ec0e04e79022c7319f8a8a2117d1da6e41c"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: AsrDrv.sys, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "c0125b2f9a60353e3fec58da325ee0810b8812013d97bd316a7d1035074d31e1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv101.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_4d78327e {
    meta:
        author = "Elastic Security"
        id = "4d78327e-9d3c-4f5a-a8b0-60209183304e"
        fingerprint = "94d5224aa39581ffc9f4d70b2c8b35775a0c2bd96a964bd80338b81e854f861b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "cea231333781085538127bdcfbf49ef1d7500c057295fba061e962376e8219e6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 70 00 70 00 53 00 68 00 6F 00 70 00 44 00 72 00 76 00 31 00 30 00 33 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AppShopDrv103.pdb"
        $str2 = "AppShopDrv103 Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_ed89a6ad {
    meta:
        author = "Elastic Security"
        id = "ed89a6ad-617b-42fb-be6a-d09be26d6093"
        fingerprint = "836f4a5d42512e54f3521c3df40b345ade8ae0cf8c5554fc2abcab9bef588270"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK INC., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "e7477a7594b976d8662aab9d4f4b110d8db135bbcd712bea391b81336dc856eb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv105n.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asrock_5ba6b4f6 {
    meta:
        author = "Elastic Security"
        id = "5ba6b4f6-6246-4601-8e64-65a5961f700c"
        fingerprint = "31380df652cbaf88c26d30ca8c60b93c3a40eafb0f4f4f6db42f4a8aaf2d8841"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASROCK Incorporation, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asrock"
        reference_sample = "ece0a900ea089e730741499614c0917432246ceb5e11599ee3a1bb679e24fd2c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 52 4F 43 4B 20 49 6E 63 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 72 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AsrDrv10.pdb"
        $str2 = "ASRock IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

