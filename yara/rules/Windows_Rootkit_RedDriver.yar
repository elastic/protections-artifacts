rule Windows_Rootkit_RedDriver_afa0359e {
    meta:
        author = "Elastic Security"
        id = "afa0359e-8d17-47ee-b81d-026760cbdbb9"
        fingerprint = "9cb6aba6322fd52a3ebe654b258b10d65ce6bf68dc1107126bd0ff780d15297c"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: 湖南蓝途方鼎科技有限公司, Version: <= 2022.9.28.1648"
        threat_name = "Windows.Rootkit.RedDriver"
        reference_sample = "03a0a002c1442a0704d1ef623022bfa0e14c36b132e081ae9d9f1314bb3ad8c8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 B9 96 E5 8D 97 E8 93 9D E9 80 94 E6 96 B9 E9 BC 8E E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x1b][\x00-\x00]|[\x09-\x09][\x00-\x00][\xe6-\xe6][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x6f][\x06-\x06])[\x1c-\x1c][\x00-\x00]|[\x09-\x09][\x00-\x00][\xe6-\xe6][\x07-\x07][\x70-\x70][\x06-\x06][\x1c-\x1c][\x00-\x00])/
        $str1 = "FilDriverx64_win10.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

rule Windows_Rootkit_RedDriver_d4f2aaba {
    meta:
        author = "Elastic Security"
        id = "d4f2aaba-f4eb-4eb8-bfce-24520da5c23e"
        fingerprint = "f151c9ed6463b5476582f39e4f74b8053057411d954f7d43a9f1cb468a827555"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: QQ 2062956250, Version: <= 3.0.0.0"
        threat_name = "Windows.Rootkit.RedDriver"
        reference_sample = "55d9a37c73d5543359ee186feb4979ccd84bff0abd997c58790d6d2c21916c29"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 51 51 20 32 30 36 32 39 35 36 32 35 30 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

