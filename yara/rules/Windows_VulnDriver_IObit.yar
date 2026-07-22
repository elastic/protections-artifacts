rule Windows_VulnDriver_IObit_343b4659 {
    meta:
        author = "Elastic Security"
        id = "343b4659-26fa-42bd-93dc-685738b291a5"
        fingerprint = "c545b86cf74048a2f0e4c2ab8ae74ac8e3d0c538c1b1210de61d8ef012d710b2"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "0209934453e9ce60b1a5e4b85412e6faf29127987505bfb1185fc9296c578b09"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "IObitUnlocker" wide
        $str3 = "IObitUnlocker Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_IObit_be603988 {
    meta:
        author = "Elastic Security"
        id = "be603988-a04d-46cc-9337-464c5680f64a"
        fingerprint = "3af2a99e053c69bb32cb1b48984b7b1fab14ba0fea36484b24da0f1d50e1161d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.3.0.20"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "045fb2c3a0bd70cc3efe305d5d6e461cb69cd287f1d5cd1b15b2271fd3175617"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x13][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "Unlocker" wide
        $str3 = "Unlocker Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_IObit_dfaf6de1 {
    meta:
        author = "Elastic Security"
        id = "dfaf6de1-5bc6-4cc3-8d24-02d2ac83ed8d"
        fingerprint = "b6fe7a4c0444b8442a972b7f3b90f7749b0cc4a3a24622e15cbba00cf7feba7e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: FileUnlock.sys, Version: <= 1.3.0.15"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "0b421285589b6ca2e8c755d67806c2aaf27ae208b701473638d05b4ac5e9aa38"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 46 00 69 00 6C 00 65 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0e][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "File unlock driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_IObit_264df776 {
    meta:
        author = "Elastic Security"
        id = "264df776-8682-434b-8237-7724a81b38a4"
        fingerprint = "3cb67a7211963db14232a9d42325bd17e0145ba83339f64001f7c3d48a4c0bbb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IObit Information Technology"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "11bc55c0771d692279298211c1d434c04168e7c7f7c4328bfd600215b88c819b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 4F 62 69 74 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 }
        $str1 = "IObitUnlocker.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_IObit_4d2ac110 {
    meta:
        author = "Elastic Security"
        id = "4d2ac110-e4bc-4dcb-9ff6-74b7b5c70de0"
        fingerprint = "f2732b6db4806490669041f86b2fc9faea8cc3c0ae0dccb515567a1c4bce4023"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.3.0.15"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "1a77f9789dcb2365c38ac5ef860fecbd143dea5077da664fd56c99fd500822ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0e][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "IObitUnlocker" wide
        $str3 = "File Unlock Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_IObit_b9019dab {
    meta:
        author = "Elastic Security"
        id = "b9019dab-9393-4f22-aefe-3fb2df20a434"
        fingerprint = "ddaebbb6fb994a92ae3c32a34a97d44ade49aceaa9dc44bb66c39bb9a629b6eb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.3.0.15"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "455bd1d7bd6337c2207f8b69d85089f91697e24cd77814ecee5dbc2a3428933c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0e][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "IObitUnlocker" wide
        $str3 = "Unlock filter driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_IObit_786822b0 {
    meta:
        author = "Elastic Security"
        id = "786822b0-bbd7-450e-a76c-3623eb615bb9"
        fingerprint = "03ec950553df28b6df8dd9ff00662f2061629b8aa8503ae0e3f60fb357f564d6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitFile.sys, Version: <= 1.3.0.15"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "47bd8fa2d23bff666993e68c9e6cc08cb49b01191a71e4ba1edcc771dc3f44ab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 46 00 69 00 6C 00 65 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0e][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "Unlocker" wide
        $str3 = "Unlock filter driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_IObit_374f2cb3 {
    meta:
        author = "Elastic Security"
        id = "374f2cb3-4031-4b0f-896b-c2c3a56f8135"
        fingerprint = "b25d4a112a0fd753148ecaa410b9b2f9f7d2c7a956d165bc2661d9054366b5a3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IObit CO., LTD, Version: <= 1.2.0.2"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "4e1d75684923974c0333d33b789c5d1569ba5a39e8fa6816e825eadaeaf51a2a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 4F 62 69 74 20 43 4F 2E 2C 20 4C 54 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "Unlocker" wide
        $str3 = "Unlocker Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_IObit_7604b52b {
    meta:
        author = "Elastic Security"
        id = "7604b52b-a6bc-4271-bf1b-4c53f2d74bdd"
        fingerprint = "eacce24dc052d1b6f92619612ab0d78a16803925dac2724a380389e36d3dd08d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.3.0.20"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "98e3f4d3a2174a9872e327cb8142ab04d926043f9baaf8b1d10805e570aece91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x13][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "File unlock driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_IObit_50765d9f {
    meta:
        author = "Elastic Security"
        id = "50765d9f-78f0-4aa1-ad00-147f45657be1"
        fingerprint = "f3f688ae3372f20ef7fd8b542be59ccc50a8fffb7067a1150bde0081f4227721"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IObit Information Technology, Version: <= 1.2.0.11"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "e4a7da2cf59a4a21fc42b611df1d59cae75051925a7ddf42bf216cc1a026eadb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 4F 62 69 74 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 6F 00 6E 00 69 00 74 00 6F 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0a][\x00-\x00][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x0b-\x0b][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "WinRing0.pdb"
        $str2 = "Advanced SystemCare" wide
        $str3 = "IObit Temperature Monitor" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

