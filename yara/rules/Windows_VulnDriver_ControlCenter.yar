rule Windows_VulnDriver_ControlCenter_f11f4316 {
    meta:
        author = "Elastic Security"
        id = "f11f4316-dc88-4452-8e1e-ffb7987e42b7"
        fingerprint = "2c7735c957f86590552667ed4be46ecb2e9513d415c0a540e0eeff91f711568d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Quanta Computer Inc., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.ControlCenter"
        reference_sample = "0b12eb25db68d8714ba52583597ed20e5fab2f6e82dcd0bcb23161acb4a9a126"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 51 75 61 6E 74 61 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6E 00 74 00 72 00 6F 00 6C 00 43 00 65 00 6E 00 74 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ControlCenter.pdb"
        $str2 = "Control Center Driver" wide
        $str3 = "ControlCenter.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

