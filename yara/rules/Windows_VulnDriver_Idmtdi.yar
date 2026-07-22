rule Windows_VulnDriver_Idmtdi_322aa746 {
    meta:
        author = "Elastic Security"
        id = "322aa746-aa4d-4e6d-9ee9-143e9e97b6ae"
        fingerprint = "4aa18aa9bd07447147615b4ff0a02fe538a21704db51c40988b29d32c15cb995"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: FEI XIAO, Version: <= 6.32.3.80"
        threat_name = "Windows.VulnDriver.Idmtdi"
        reference_sample = "2c1b65c2988b337182f1ba57b404793454e30a7fd328d34bc2e79857dc437a4a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 45 49 20 58 49 41 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 64 00 6D 00 74 00 64 00 69 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1f][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x4f][\x00-\x00][\x03-\x03][\x00-\x00]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x50-\x50][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "Internet Download Manager" wide
        $str2 = "Internet Download Manager TDI Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

