rule Windows_VulnDriver_Biostar_d6cc23af {
    meta:
        author = "Elastic Security"
        id = "d6cc23af-4502-4b18-bd10-17495e6e1443"
        fingerprint = "65a66dc00e62f32fd088809f3c88ceb9d59d264ecff0d9f830c35dfa464baf43"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: BS_HWMIO64_W10.sys, Version: 10.0.1806.2200"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 48 00 57 00 4D 00 49 00 4F 00 36 00 34 00 5F 00 57 00 31 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x98][\x00-\x08]|[\x00-\xff][\x00-\x07])([\x00-\x0e][\x00-\x07]|[\x00-\xff][\x00-\x06])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0d][\x00-\x07]|[\x00-\xff][\x00-\x06]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_68682378 {
    meta:
        author = "Elastic Security"
        id = "68682378-9b49-4bec-b24c-aba8221a62fe"
        fingerprint = "df974c8b5bb60b1b6e95d1c70c968dfca1f1e351f50eed29d215da673d45af19"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: BS_I2cIo.sys, Version: 1.1.0.0"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 49 00 32 00 63 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_684a5123 {
    meta:
        author = "Elastic Security"
        id = "684a5123-cd84-4133-9530-30bfefd5ad1b"
        fingerprint = "c92b058bbc8a708431bdbe8fc2e793c0a424aa79b25892c83153ffd32e1a89d3"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: BS_RCIO64.sys, Version: 10.0.0.1"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 52 00 43 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_e0b6cf55 {
    meta:
        author = "Elastic Security"
        id = "e0b6cf55-c97d-4799-88a6-30ab0e880b0b"
        fingerprint = "c38c456a008b847c42c45f824b125e7308b8aa41771d3db3d540690b13147abc"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "73327429c505d8c5fd690a8ec019ed4fd5a726b607cabe71509111c7bfe9fc7e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\BS_RCIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_Biostar_b98e13a3 {
    meta:
        author = "Elastic Security"
        id = "b98e13a3-03f2-4d75-b8ae-183643f467de"
        fingerprint = "b1ef9b5fe9b546066319a4e5472cc78a367a119e70f0995fb7285c9b5d007659"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Biostar Microtech Int'l Corp"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "362c4f3dadc9c393682664a139d65d80e32caa2a97b6e0361dfd713a73267ecc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 69 6F 73 74 61 72 20 4D 69 63 72 6F 74 65 63 68 20 49 6E 74 27 6C 20 43 6F 72 70 }
        $str1 = "BS_RCIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Biostar_f6f5933a {
    meta:
        author = "Elastic Security"
        id = "f6f5933a-3c9d-4530-9ccc-ace220c058d0"
        fingerprint = "3ded19a80b89d8344d2e8d73033efe2e136792081699f5330000cb7b893a6612"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BIOSTAR MICROTECH INT'L CORP, Version: <= 1.1.0.0"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "42e170a7ab1d2c160d60abfc906872f9cfd0c2ee169ed76f6acb3f83b3eeefdb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 49 4F 53 54 41 52 20 4D 49 43 52 4F 54 45 43 48 20 49 4E 54 27 4C 20 43 4F 52 50 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 49 00 32 00 63 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "BS_I2cIo.pdb"
        $str2 = "BIOSTAR I/O driver fle" wide
        $str3 = "I/O Interface driver file" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Biostar_083188de {
    meta:
        author = "Elastic Security"
        id = "083188de-6e71-48fc-b6c9-dee7b94d875a"
        fingerprint = "16cac9ca74a1ca113d1f63e4611b784858cc7e1f3c0fa85c1ca3556e2904e0ef"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BIOSTAR MICROTECH INT'L CORP"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 49 4F 53 54 41 52 20 4D 49 43 52 4F 54 45 43 48 20 49 4E 54 27 4C 20 43 4F 52 50 }
        $str1 = "BS_HWMIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Biostar_5ba03dcb {
    meta:
        author = "Elastic Security"
        id = "5ba03dcb-1499-4ffa-936f-97f7ea0dce0d"
        fingerprint = "d86278acc0eba81f50486fe3be0e0aa30a7af766956eb1aba23b8865fe92a4dc"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BIOSTAR MICROTECH INT'L CORP"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "6dafd15ee2fbce87fef1279312660fc399c4168f55b6e6d463bf680f1979adcf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 49 4F 53 54 41 52 20 4D 49 43 52 4F 54 45 43 48 20 49 4E 54 27 4C 20 43 4F 52 50 }
        $str1 = "BS_HWMIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Biostar_afac269b {
    meta:
        author = "Elastic Security"
        id = "afac269b-83dc-4132-a2aa-f4323867df2a"
        fingerprint = "db6bcc2e86a70150e775e5a0d685eb213600a1eae07dfcffa8d82a4b939e9495"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 10.0.1806.2200"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "7c6f16af074c3f1c74fc69734f1c8b8a03b0594ac2085d5a0c582fc8cc378858"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 52 00 43 00 49 00 4F 00 36 00 34 00 5F 00 57 00 31 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\x0d][\x07-\x07])|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x97][\x08-\x08])[\x0e-\x0e][\x07-\x07]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x98-\x98][\x08-\x08][\x0e-\x0e][\x07-\x07])/
        $str1 = "BS_RCIO64_W10.pdb"
        $str2 = "BIOSTAR I/O driver" wide
        $str3 = "I/O Interface driver file" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Biostar_881dc820 {
    meta:
        author = "Elastic Security"
        id = "881dc820-9a0e-4b90-bae9-234f4abbadd6"
        fingerprint = "b1dcfff984f433943cb1ad449df00d5c94f85660d83808c6a895cf73e6c2f281"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BIOSTAR MICROTECH INT'L CORP"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "86a8e0aa29a5b52c84921188cc1f0eca9a7904dcfe09544602933d8377720219"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 49 4F 53 54 41 52 20 4D 49 43 52 4F 54 45 43 48 20 49 4E 54 27 4C 20 43 4F 52 50 }
        $str1 = "BS_Flash64.pdb"
        $str2 = "\\Device\\BS_Flash64"
        $str3 = "\\DosDevices\\BS_Flash64"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Biostar_1b60af04 {
    meta:
        author = "Elastic Security"
        id = "1b60af04-2e98-4672-b660-f45d91104fcf"
        fingerprint = "386768eae2c581d29dde0f18e1796885b4a48c6bdac9e682d2d7fbf3dff2cbac"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 10.0.0.0"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "a8aae612727320db096b337a45bf3cd31b5f9702ef6c4747dd2aaa74ff6badb7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 52 00 56 00 53 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "BS_RVSIO64.pdb"
        $str2 = "BIOSTAR I/O driver" wide
        $str3 = "I/O Interface driver file" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Biostar_3340ae10 {
    meta:
        author = "Elastic Security"
        id = "3340ae10-27a4-4a2c-91f1-6e0dc0477781"
        fingerprint = "ddf26c24d7cc076fdfb5b398b94356ebe68f627d3c8c50e0ce195acf60028dc9"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BIOSTAR MICROTECH INT'L CORP"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "d55b675941da4cc9be05f2ef7cea15784074772da585e5bf56d5be15afde4789"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 49 4F 53 54 41 52 20 4D 49 43 52 4F 54 45 43 48 20 49 4E 54 27 4C 20 43 4F 52 50 }
        $str1 = "BS_RCIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Biostar_dad1bbdb {
    meta:
        author = "Elastic Security"
        id = "dad1bbdb-b5c6-4fb1-99e1-1c062f1f3ad4"
        fingerprint = "2167eeda9399712fb95a3190aa084ecc8ca10829129fca7deb3bfffc22f24b5c"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BIOSTAR MICROTECH INT'L CORP, Version: <= 1.1.0.0"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 49 4F 53 54 41 52 20 4D 49 43 52 4F 54 45 43 48 20 49 4E 54 27 4C 20 43 4F 52 50 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 49 00 32 00 63 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "BSMEMx64.pdb"
        $str2 = "BIOSTAR I/O driver fle" wide
        $str3 = "I/O Interface driver file" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

