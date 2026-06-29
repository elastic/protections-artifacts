rule Windows_VulnDriver_AsmIo_8c6a94eb {
    meta:
        author = "Elastic Security"
        id = "8c6a94eb-20e3-4644-a767-107f42233ff1"
        fingerprint = "65c817961c3442b18624ff93b344c4c1dce6a20c90a959e6bf7cd1b140820adb"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASMedia Technology Inc., Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.AsmIo"
        reference_sample = "e4658d93544f69f5cb9aa6d9fec420fecc8750cb57e1e9798da38c139d44f2eb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 4D 65 64 69 61 20 54 65 63 68 6E 6F 6C 6F 67 79 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 6D 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "AsmIo.pdb"
        $str2 = "IOCTL_ASMIO_SET_DEBUG_LEVEL"
        $str3 = "IOCTL_ASMIO_WRITE_MEM"
        $str4 = "Asmedia PCI Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

