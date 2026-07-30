rule Windows_VulnDriver_Supermicro_350147cf {
    meta:
        author = "Elastic Security"
        id = "350147cf-acea-4650-97ff-f927647de5fe"
        fingerprint = "d938406d1a7dac79e74248fa3e946251edc533c0dde008605774173ccc1fd068"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Super Micro Computer, Inc."
        threat_name = "Windows.VulnDriver.Supermicro"
        reference_sample = "a6f8aa3de5b4aea58eddd45807d722c864d4bc4a38ad573174af864e21f0d526"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 70 65 72 20 4D 69 63 72 6F 20 43 6F 6D 70 75 74 65 72 2C 20 49 6E 63 2E }
        $str1 = "superbmc.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Supermicro_02ffc158 {
    meta:
        author = "Elastic Security"
        id = "02ffc158-c409-4666-9a9c-5074b0826bd1"
        fingerprint = "9f3276de08136f4a90c86d70faee0195a159f221c2d9e95348c730d6d88c1b5b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Super Micro Computer, Inc."
        threat_name = "Windows.VulnDriver.Supermicro"
        reference_sample = "d6518cb6dc0cfdfefb9e2210e3de18867748a77153fa11bc7263cdbc58919815"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 70 65 72 20 4D 69 63 72 6F 20 43 6F 6D 70 75 74 65 72 2C 20 49 6E 63 2E }
        $str1 = "WinIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Supermicro_2bc17577 {
    meta:
        author = "Elastic Security"
        id = "2bc17577-c7ed-43b1-87c4-df2b15f1ae45"
        fingerprint = "6a2f1a8660aef62cc9a3f999f57718576d8eee82843db097896136982b1767fe"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Super Micro Computer, Inc., Version: <= 2.0.0.0"
        threat_name = "Windows.VulnDriver.Supermicro"
        reference_sample = "f8430bdc6fd01f42217d66d87a3ef6f66cb2700ebb39c4f25c8b851858cc4b35"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 70 65 72 20 4D 69 63 72 6F 20 43 6F 6D 70 75 74 65 72 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 75 00 70 00 65 00 72 00 62 00 6D 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "superbmc" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

