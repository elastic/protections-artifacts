rule Windows_VulnDriver_GPUZ_cfb9c8d6 {
    meta:
        author = "Elastic Security"
        id = "cfb9c8d6-caf0-4747-98ad-555827dcd0ad"
        fingerprint = "773e5b1a68ac89c803cb0a23e1f6a6bf18f15c6f3b1c773b4ddab9a30993db3a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: TechPowerUp LLC, Version: <= 7.2.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "69fb21e4c8dbfcab838d53d98ec7357d35e30cbbe5fde9e26457d79242ddd78e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 20 4C 4C 43 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "driver-x64.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GPUZ_f6e00dd7 {
    meta:
        author = "Elastic Security"
        id = "f6e00dd7-2567-4b51-8171-691dfc4a3385"
        fingerprint = "003fa34df3656d75c760857175b2b805c4162b63486d386c9e0a0d0208ff7b29"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: techPowerUp, Version: <= 1.25.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "7b1529da3469a46d738a20b98e49f78e1b24aed34a62ea5440db78ccda73e972"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 74 65 63 68 50 6F 77 65 72 55 70 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x18][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x19-\x19][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Release64.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GPUZ_40dcce91 {
    meta:
        author = "Elastic Security"
        id = "40dcce91-9e37-48a3-adcf-247b7e674b00"
        fingerprint = "91d5c941ae3ec91c2e947f94403ab44dc6e2e1c70db4a06a971dd0ecb32aed3a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: TechPowerUp LLC, Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "7d39223e7eb902712aeac77c90b9fa00a6e5e56a68d4c542bcc88556a57ba735"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 20 4C 4C 43 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GPUZ_e232b366 {
    meta:
        author = "Elastic Security"
        id = "e232b366-f5c1-42e3-aa24-8158efc16da2"
        fingerprint = "b766128734de88d534ac44feb7d697d5bbeef833f340437b56b873c9329f5049"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: TechPowerUp LLC, Version: <= 5.0.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "9af0b89c5c54eb66e5a660b61aee7c1a25b1c92e20a310d8b16552abcf90c0b5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 20 4C 4C 43 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GPUZ_33b61c58 {
    meta:
        author = "Elastic Security"
        id = "33b61c58-5036-45a5-81c6-229c84dae212"
        fingerprint = "2af17e05d854189048a469724cfca891437260fae4796d20945f8b23e2c7b78e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: TechPowerUp, Version: <= 1.60.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "f9418b5e90a235339a4a1a889490faca39cd117a51ba4446daa1011da06c7ecd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x3b][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x3c-\x3c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

