rule Windows_VulnDriver_FoxKeDriver64_e219fa9b {
    meta:
        author = "Elastic Security"
        id = "e219fa9b-ce56-4632-bc6c-60bcc6c3d598"
        fingerprint = "ecff60b3c5520533c8d2f5d95b927d8beae0fa31ad1773ef3edbde2a887b9945"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HongFuTai Precision Electrons (YanTai) Co. Ltd, Version: <= 1.0.1.3"
        threat_name = "Windows.VulnDriver.FoxKeDriver64"
        reference_sample = "eb81e127e7a46c80acdf8a3fc24a350381f24acb06f0fdf9fdcd34ce9b08d084"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 6F 6E 67 46 75 54 61 69 20 50 72 65 63 69 73 69 6F 6E 20 45 6C 65 63 74 72 6F 6E 73 20 28 59 61 6E 54 61 69 29 20 43 6F 2E 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 46 00 6F 00 78 00 4B 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "FoxG1Driver64.pdb"
        $str2 = "\\Device\\Fox_FOXONE_Driver"
        $str3 = "\\DosDevices\\Fox_FOXONE_Driver"
        $str4 = "Foxconn (R) Kernel Driver(64bit)" wide
        $str5 = "Foxconn Kernel Driver(64bit)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

