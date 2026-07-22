rule Windows_VulnDriver_Nvidia_36de2baa {
    meta:
        author = "Elastic Security"
        id = "36de2baa-1e66-4776-b8c9-bbbfbc7f9d4c"
        fingerprint = "15a59b68e00d299041ba33348c191f742788199cf95209288e4860d4e4822811"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "159dcf37dc723d6db2bad46ed6a1b0e31d72390ec298a5413c7be318aef4a241"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "nvflash.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Nvidia_347c169b {
    meta:
        author = "Elastic Security"
        id = "347c169b-54a3-41fc-8861-4fa1b5db38f8"
        fingerprint = "14e7e2948f779de4912dfb5e1809569c37ccb74be93c6ced399aafc1a9c0e814"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: nvoclock.sys, Version: <= 6.2.15.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "16ae28284c09839900b99c0bdf6ce4ffcd7fe666cfd5cfb0d54a3ad9bea9aa9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_f0d13fb2 {
    meta:
        author = "Elastic Security"
        id = "f0d13fb2-baa7-417d-94d8-8a4e5d71f51c"
        fingerprint = "d2f52563240d7ee2f75c2bb103e2068e0240a553da48aad1655e63867743cef6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: NVoclock.RC, Version: <= 5.0.1636.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "2203bd4731a8fdc2a1c60e975fd79fd5985369e98a117df7ee43c528d3c85958"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 56 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 52 00 43 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x63][\x06-\x06])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x64-\x64][\x06-\x06]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x64-\x64][\x06-\x06])/
        $str1 = "nvoclk64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_a23a3872 {
    meta:
        author = "Elastic Security"
        id = "a23a3872-24ac-4164-b867-3f74d476f85d"
        fingerprint = "126a12b57ac2afd8e9d60624ec7b56550bd29f91df94c5461b0b470c018610d8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "506f953bbb285aeb8af0549eb24f52f3b7af36afe740afa36735bac70573ce28"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "AsIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Nvidia_170457ac {
    meta:
        author = "Elastic Security"
        id = "170457ac-67b4-432d-a6d2-c7589c8a9062"
        fingerprint = "d7d34ad010604da4c83b12ad2fa47c30a4d0c82137bd90763ba2fdff5ad19550"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 6.5.6.6"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "642857fc8d737e92db8771e46e8638a37d9743928c959ed056c15427c6197a54"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x05][\x00-\x00][\x06-\x06][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "nvoclk64.pdb"
        $str2 = "NVIDIA System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_817183b1 {
    meta:
        author = "Elastic Security"
        id = "817183b1-c0c8-431b-8295-c5f7d71a1a0c"
        fingerprint = "b271cc6dcf41407cdcd591dac6d9bafdeb316e51b593087367a0c1c6b9cae7ed"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 6.5.0.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "848b150ffcf1301b26634a41f28deacb5ccdd3117d79b590d515ed49849b8891"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "nvflsh64.pdb"
        $str2 = "NVIDIA System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_f058fb9a {
    meta:
        author = "Elastic Security"
        id = "f058fb9a-9537-4a3d-8c3e-7f8fc555f9bd"
        fingerprint = "72be939136c685bbacdb3584e2194bfb48aa56a9d775a2c718c1c4cb5de5ec39"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: nvoclock.sys, Version: <= 6.3.6.0"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "909f6c4b8f779df01ef91e549679aa4600223ac75bc7f3a3a79a37cee2326e77"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVIDIA System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_e168b0f3 {
    meta:
        author = "Elastic Security"
        id = "e168b0f3-0c2a-4036-86e5-b9d9507e0126"
        fingerprint = "9f335d8a64c47b82b8f5576ec2f47fa286a81267341a4d2d905dcde388566b6f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: nvoclock.sys, Version: <= 7.0.0.32"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "979017192bb021026dc9640a9ab43b24df445a07acbf6c5a4222e4486eb25d3d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x1f][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x20-\x20][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "nvr0int64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_27f9d249 {
    meta:
        author = "Elastic Security"
        id = "27f9d249-9a80-41ad-bda8-e1d07607a52d"
        fingerprint = "620e2617b2962861fd37cf436d4f4ca75fdc5f5836e24d7f92e9e9caf2b777a5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 1.8.0.0"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "afdd66562dea51001c3a9de300f91fc3eb965d6848dfce92ccb9b75853e02508"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 66 00 6C 00 61 00 73 00 68 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NVIDIA Flash Driver" wide
        $str2 = "NVIDIA Flash Driver, Version 1.8.0" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_7f6bfd41 {
    meta:
        author = "Elastic Security"
        id = "7f6bfd41-797a-42a2-a36b-42961c669fc4"
        fingerprint = "7c0808d272186bf4d7793931a33af4441089f35ed0c3c300f9d9245b008ec48d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 6.2.15.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d54ac69c438ba77cde88c6efd6a423491996d4e8a235666644b1db954eb1da9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00])/
        $str1 = "nvoclk64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_2ce83255 {
    meta:
        author = "Elastic Security"
        id = "2ce83255-c3a7-4a32-8b36-12285973d1fb"
        fingerprint = "09ade361722fdaabf3e07990a79fc8be000b444e387b07264eb9fde3033a0a62"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Micro-Star Int'l Co., Ltd., Version: <= 5.0.6.6"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d633055c7eda26dacfc30109eb790625519fc7b0a3a601ceed9e21918aad8a1b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 2D 53 74 61 72 20 49 6E 74 27 6C 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x05][\x00-\x00][\x06-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "nvoclk64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_cd78de23 {
    meta:
        author = "Elastic Security"
        id = "cd78de23-7b85-4e23-8b61-a0df6dfa7d68"
        fingerprint = "1c8f034cdb044f2fd22f60f1e22a343745ca14476cf84152064919668b6e0ac7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d7c81b0f3c14844f6424e8bdd31a128e773cb96cccef6d05cbff473f0ccb9f9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "KApcHelper.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Nvidia_f76944d7 {
    meta:
        author = "Elastic Security"
        id = "f76944d7-9eff-40d1-bc54-d6cb35d14225"
        fingerprint = "f59234d5b150b1fcf31ed3ec16643a46e848b56248d1cc80f14466df3bc5b2f5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: NVoclock.RC, Version: <= 5.0.1636.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d7c90cf3fdbbd2f40fe6a39ad0bb2a9a97a0416354ea84db3aeff6d925d14df8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 56 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 52 00 43 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x63][\x06-\x06])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x64-\x64][\x06-\x06]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x64-\x64][\x06-\x06])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Nvidia_a67b7462 {
    meta:
        author = "Elastic Security"
        id = "a67b7462-14e8-4ad4-bf3c-52d135e0feba"
        fingerprint = "a47ee83093a1a792128131d0054471cd9866816180b6919627b004327c4d31c9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 6.5.6.6"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "f4e500a9ac5991da5bf114fa80e66456a2cde3458a3d41c14e127ac09240c114"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x05][\x00-\x00][\x06-\x06][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVIDIA System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

