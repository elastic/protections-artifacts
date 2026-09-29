rule Windows_VulnDriver_Xhunter_197ce145 {
    meta:
        author = "Elastic Security"
        id = "197ce145-3854-45f9-ba85-3fd501018b42"
        fingerprint = "c6398a069038b30461d447c31bd210c1718bbeb2c07853f2eb0f4151a20e5705"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: Wellbia.com Co., Ltd., Version: <= 3.4.2.150"
        threat_name = "Windows.VulnDriver.Xhunter"
        reference_sample = "e727d0753d2cd0b2f6eeba4cea53aa10b3ff3ed2afeb78f545fcf6d840f85c3e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 65 6C 6C 62 69 61 2E 63 6F 6D 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 78 00 68 00 75 00 6E 00 74 00 65 00 72 00 31 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x95][\x00-\x00][\x02-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x96-\x96][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "xhunter64.pdb"
        $str2 = "XIGNCODE3" wide
        $str3 = "XIGNCODE3 System Guard" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Xhunter_82d298ea {
    meta:
        author = "Elastic Security"
        id = "82d298ea-b18d-47b1-a309-5f8c6baecd9e"
        fingerprint = "ec35af7115ab67958c07193f53cfc56f0c1bf6dcbcc3a3b69f01e6c60011772d"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Name: xhunter1.sys, Version: <= 3.4.2.150"
        threat_name = "Windows.VulnDriver.Xhunter"
        reference_sample = "3f12ec735d52e1096c88a64e0ab5a3adde242a91fd742c901d58b5e5dc4cb6c8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 78 00 68 00 75 00 6E 00 74 00 65 00 72 00 31 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x95][\x00-\x00][\x02-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00][\x96-\x96][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "xhunter64.pdb"
        $str2 = "XIGNCODE3" wide
        $str3 = "XIGNCODE3 System Guard" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Xhunter_b3a5ed35 {
    meta:
        author = "Elastic Security"
        id = "b3a5ed35-94b9-439c-a12b-606d30602fd3"
        fingerprint = "d22746d8f8c510102f53cde1481dc9d1c21e30c2f54072c246ad15f351c1daba"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: Wellbia.com Co., Ltd., Version: <= 2026.6.1.192"
        threat_name = "Windows.VulnDriver.Xhunter"
        reference_sample = "44cefb0b3b6516e6731de09a3e2e0eb8b98b02cc3fdf7bb4b22680e93f3cde1e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 65 6C 6C 62 69 61 2E 63 6F 6D 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 78 00 68 00 75 00 6E 00 74 00 65 00 72 00 31 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe9][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\xea-\xea][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\xea-\xea][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x06-\x06][\x00-\x00][\xea-\xea][\x07-\x07][\x00-\xbf][\x00-\x00][\x01-\x01][\x00-\x00]|[\x06-\x06][\x00-\x00][\xea-\xea][\x07-\x07][\xc0-\xc0][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "Wellbia.com System Guard" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

