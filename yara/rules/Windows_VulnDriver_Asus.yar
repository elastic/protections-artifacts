rule Windows_VulnDriver_Asus_7cf9d3b1 {
    meta:
        author = "Elastic Security"
        id = "7cf9d3b1-cdf9-4af1-98eb-ab8703b3731a"
        fingerprint = "1d1a2163ea510dd082a9c647c4b9d1c009f3c8b31d2147446f4cd242b6e7dfcd"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "03a1e1037ea162020e75e37be771f620c4569e9621175f672583705f3ab569f7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO3_32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_c790c867 {
    meta:
        author = "Elastic Security"
        id = "c790c867-8d34-4866-8f4d-e3b350b7adb0"
        fingerprint = "5b31f170d9b02cc31021c7c23aba7cd15c7cbb10074e0502517733bbb529adb8"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 1.4.0.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "04e9a85d89a5119ff2dd2342719f6129d42627e3083559c88d4f3be607dd1f06"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 4D 00 61 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IOMap.pdb"
        $str2 = "ASUS Kernel Mode Driver for Windows" wide
        $str3 = "ASUS Kernel Mode Driver for NT " wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Asus_68f390a5 {
    meta:
        author = "Elastic Security"
        id = "68f390a5-4056-4156-806b-c569d4a0f146"
        fingerprint = "98b17a57090995dd1d28a678d536e0e3ba92cd91ef2767ff05107ed9ddfe3931"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 0.2.1.7"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "0da746e49fd662be910d0e366934a7e02898714eaaa577e261ab40eb44222b5c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x06][\x00-\x00][\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "ATSZIO.pdb"
        $str2 = "ATSZIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asus_998862dc {
    meta:
        author = "Elastic Security"
        id = "998862dc-d96c-4013-a8de-99e7cbe8649f"
        fingerprint = "5aed9446e0198c3d94518ee996e03e3d6fc4c56a850d540c05c6de321b160709"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "13ae4d9dcacba8133d8189e59d9352272e15629e6bca580c32aff9810bd96e44"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "TdeIo64.pdb"
        $str2 = "IOCTL_INDEXIO_WRITE_DWORD"
        $str3 = "IOCTL_INDEXIO_READ_DWORD"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Asus_e62a0424 {
    meta:
        author = "Elastic Security"
        id = "e62a0424-0fb5-4213-936e-a4008fc59b4b"
        fingerprint = "89ec249f0f695aa14bda0eeb2aa231cf9d840be697d54654fd0a91b98f8d6fc7"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 6.32.0.1"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 50 00 55 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1f][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "WCPU.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "ASUS TDE CPU Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Asus_db226282 {
    meta:
        author = "Elastic Security"
        id = "db226282-e1d5-4157-8e47-141378a88890"
        fingerprint = "d835114d0bfc01dac370f58200dd93c9ffe4f0c2f6dcb2602ac5fc911f7e116a"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTEK COMPUTER INC., Version: <= 1.9.7.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "1fac3fab8ea2137a7e81a26de121187bf72e7d16ffa3e9aec3886e2376d3c718"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 45 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "EIO.pdb"
        $str2 = "ASUS VGA Kernel Mode Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asus_25621f13 {
    meta:
        author = "Elastic Security"
        id = "25621f13-ddaa-475c-ab1c-da9ed8bfde21"
        fingerprint = "155f9965273e3edfe33b9166e5e64c73e717e5de637487a40a7f9a5a060ac03e"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "218de0c801b70d8bebf0233f796de07842b84b899c49f7a7be1c0423a158b786"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $str1 = "AsIO3_32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_58d896dc {
    meta:
        author = "Elastic Security"
        id = "58d896dc-dae9-4689-9688-53cbd02a725b"
        fingerprint = "51ca96ffaae4d15369c47be928cb0b1fb26cde7c6e0aa305ba7e461e516d5a61"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "26453afb1f808f64bec87a2532a9361b696c0ed501d6b973a1f1b5ae152a4d40"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO3_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_308741d3 {
    meta:
        author = "Elastic Security"
        id = "308741d3-cc20-4709-9de5-262e75a42636"
        fingerprint = "e52e88840392901254b714ff9bdb4acfd3aac15bb1ccef61d9aee0205ba68906"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "2d195cd4400754cc6f6c3f8ab1fe31627932c3c1bf8d5d0507c292232d1a2396"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $str1 = "AsIO3_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_81ba2bde {
    meta:
        author = "Elastic Security"
        id = "81ba2bde-7ba2-4f26-95c1-f565566848b4"
        fingerprint = "645dd8d992a60fab02e8bc6ccafc569c135d86354398e056ae4967fd77ad0c6d"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "38c18db050b0b2b07f657c03db1c9595febae0319c746c3eede677e21cd238b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "Drv.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Asus_d41d124b {
    meta:
        author = "Elastic Security"
        id = "d41d124b-51d9-4f29-99cf-01512ea74b72"
        fingerprint = "c18520e395f35328e8bfcbbd85842b620c2d83db8d2900fc4676725df506dd5d"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "41765151df57125286b398cc107ff8007972f4653527f876d133dac1548865d6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_9bf33615 {
    meta:
        author = "Elastic Security"
        id = "9bf33615-f7e6-4387-a9fd-ae6d8872430d"
        fingerprint = "9a2c193e56b5cb641fde7eb39093189b36035e66acb6fb21638a354f1eb30ea1"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 2.5.0.1"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "42851a01469ba97cdc38939b10cf9ea13237aa1f6c37b1ac84904c5a12a81fa0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 72 00 69 00 76 00 65 00 72 00 37 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver7.pdb"
        $str2 = "The driver for the ECtool driver-based tools" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asus_d41768bf {
    meta:
        author = "Elastic Security"
        id = "d41768bf-e91e-4ae7-b98e-9b0061f4ac36"
        fingerprint = "0734b9545b8b8fff3d9f7d4eec29ae873d01406d8a2dbcce4071ede226f0ff03"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "61a1bdddd3c512e681818debb5bee94db701768fc25e674fcad46592a3259bd0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "GLCKIO2.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_f9ef4fe1 {
    meta:
        author = "Elastic Security"
        id = "f9ef4fe1-1caf-4200-8c52-f0c812ad2411"
        fingerprint = "9be8864dd319e091d008d448e6bb6edd5638f7d63a7e8044787832f2c9f02edc"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "72322fa8bba20df6966acbcf41e83747893fd173cd29de99b5ad1a5d3bf8f2de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "Asushwio2.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_a4b6c6c9 {
    meta:
        author = "Elastic Security"
        id = "a4b6c6c9-7e5f-4e19-b4e4-c263fe851f0c"
        fingerprint = "502bc2770b386ab8122ce38f1d17c26d3e7e4b0a8f0f2e9ed4a7818b4d34b88a"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "8f23313adb35782adb0ba97fefbfbb8bbc5fc40ae272e07f6d4629a5305a3fa2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsUpIO64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_72ed6b44 {
    meta:
        author = "Elastic Security"
        id = "72ed6b44-ca6b-4e09-8bcd-e26bee804a40"
        fingerprint = "799bbd30cf1936d446c9140ff018c5e550e3974b1504ffa5f56c1834561e281b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "a7860e110f7a292d621006b7208a634504fb5be417fd71e219060381b9a891e6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsIO2_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_1970c0aa {
    meta:
        author = "Elastic Security"
        id = "1970c0aa-c445-42a4-ad54-2bfe0c1bb6f2"
        fingerprint = "bed82c63f4d8ce42b1f2aa0e9b8f027359d93c8066fbe8b3d6509133260a6fb2"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc."
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $str1 = "AsUpIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Asus_c9460197 {
    meta:
        author = "Elastic Security"
        id = "c9460197-8e24-4c8d-9832-3c6c6346a0c9"
        fingerprint = "7f4cbf351b9f2263d7736e46866a63f20aca8dc941e70de898481fda0be2f0f2"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: EIO.sys, Version: <= 1.9.7.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "cf69704755ec2643dfd245ae1d4e15d77f306aeb1a576ffa159453de1a7345cb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "EIO.pdb"
        $str2 = "ASUS VGA Kernel Mode Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asus_18ff3160 {
    meta:
        author = "Elastic Security"
        id = "18ff3160-6b25-4551-a4fa-0cef1c57edb0"
        fingerprint = "dfb4dd9827d148c54044b171fe4dc94296112e04da0e10607d633a3089b9f4c0"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC., Version: <= 0.2.1.7"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "e2269e38a00f5328d07af80edb21bb92259b015789f1ab1d7131505a5bc58216"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x06][\x00-\x00][\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "ATSZIO64.pdb"
        $str2 = "ATSZIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asus_f2e2b71a {
    meta:
        author = "Elastic Security"
        id = "f2e2b71a-6fd9-4d99-85c0-78610a3d1248"
        fingerprint = "c0460f0545a62abc39ed0dfb7425584922c19d2a02f3caf13167a39f24105881"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC., Version: <= 2.5.0.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "e62d0c1353a3d913497e6016d0f48d7cf9ef99e4026b94ccd873d6c7a9a54565"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 4D 00 61 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IOMap.pdb"
        $str2 = "ASUS Kernel Mode Driver for Windows" wide
        $str3 = "ASUS Kernel Mode Driver for NT " wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Asus_d5da465b {
    meta:
        author = "Elastic Security"
        id = "d5da465b-2f02-42c4-87a8-1fa912290b94"
        fingerprint = "33d436d9d53bed8f5b10a0f94f63c0764f6b071343a8525c1c781d893f069c50"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "ea85bbe63d6f66f7efee7007e770af820d57f914c7f179c5fee3ef2845f19c41"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 4D 00 61 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IOMap.pdb"
        $str2 = "ASUS Kernel Mode Driver for NT " wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Asus_1d4d083e {
    meta:
        author = "Elastic Security"
        id = "1d4d083e-1631-460d-bd48-2d736b612518"
        fingerprint = "2e6af17c557184e4719d230dffca60fbaa3c77d67af1ed0585c9f68da083108e"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 0.2.2.3"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "fb6b0d304433bf88cc7d57728683dbb4b9833459dc33528918ead09b3907ff22"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "ATSZIO64.pdb"
        $str2 = "ATSZIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

