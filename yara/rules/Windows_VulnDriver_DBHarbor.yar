rule Windows_VulnDriver_DBHarbor_1b9535a2 {
    meta:
        author = "Elastic Security"
        id = "1b9535a2-49ae-4d3f-97b2-9c448474e0b6"
        fingerprint = "c5860ef3db246ee80e821cb9d4d7f31d7e4cb5fa097d490ea2c074bc205aaa82"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "083ff41609e2c0402f20cc00da1110a0cb80c515ca1c2f551606ecc94986cff9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetector.pdb"
        $str2 = "SysInfo Detector" wide
        $str3 = "Driver for SysInfo Detector" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_DBHarbor_325979aa {
    meta:
        author = "Elastic Security"
        id = "325979aa-1694-4428-b4d1-2942b14a56d7"
        fingerprint = "1a688d59d3038ece102987b715c1fe526f44e57b825aedea4e3394ad5efc5021"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "33a73e36499d4a33f9321c5ac40a4e34c029a2d7ea26205a245592df78195776"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 41 00 45 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetectorAEx64.pdb"
        $str2 = "SysInfo Auditor" wide
        $str3 = "Driver for SysInfo Detector Pro" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_DBHarbor_e59965f8 {
    meta:
        author = "Elastic Security"
        id = "e59965f8-2f08-4494-b280-4bc014664988"
        fingerprint = "a17fe043e0e86d575581190a52e51e49ccb51a5dee3bf28212ec1d9981502c1d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "45e5977b8d5baec776eb2e62a84981a8e46f6ce17947c9a76fa1f955dc547271"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetectorX64.pdb"
        $str2 = "SysInfo Detector" wide
        $str3 = "Driver for SysInfo Detector" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_DBHarbor_d38f7611 {
    meta:
        author = "Elastic Security"
        id = "d38f7611-0fdc-4e27-b9cd-2f91ac92d78e"
        fingerprint = "a81798c45a1a434e293c4891f6bbc751dce7afeaaa7cf95710d9118633cc7ce6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "5b0ebf255769224b95d23ff0511014ae80ad8778737d6aaa071aeb794012b058"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 50 00 72 00 6F 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetectorProX64.pdb"
        $str2 = "SysInfo Detector Pro" wide
        $str3 = "Driver for SysInfo Detector Pro" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_DBHarbor_3815ce85 {
    meta:
        author = "Elastic Security"
        id = "3815ce85-2b60-42c6-a553-9149870a94a1"
        fingerprint = "d924670e1a665cd73e713ccb78773522babaf2eb83eaf4067a8bd25d5fb046b5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "770ab79212b08cd13864d6cfd9b97180d7b3f084d1d44aec09c8314d9466039e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 41 00 45 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetectorAE.pdb"
        $str2 = "SysInfo Auditor" wide
        $str3 = "Driver for SysInfo Detector Pro" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_DBHarbor_b0516000 {
    meta:
        author = "Elastic Security"
        id = "b0516000-950f-4b98-85e4-491ca9bb01d9"
        fingerprint = "c429aaa62ba67226d2342ba821147c9aa7b2a79db51ba8681a13589628c3627a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "8ec9a4c4ec2b73440c591bc91543d0f685ffa1c3658926b25b06d929c5b6feed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 50 00 72 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetectorPro.pdb"
        $str2 = "SysInfo Detector Pro" wide
        $str3 = "Driver for SysInfo Detector Pro" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

