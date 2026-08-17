rule Windows_VulnDriver_SparkIO_0efefde4 {
    meta:
        author = "Elastic Security"
        id = "0efefde4-de00-4847-b694-688c84d6b88b"
        fingerprint = "482813e84edc983d52d0f0d9e834aca42ef14763c20ffc902ef6a6e3f26e7183"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.SparkIO"
        reference_sample = "5a40ee54b975ec19b40dcc0b75f86fd403c829b043a20ac67b7345a6b967c4b3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $pdb_path = "E:\\ToolSrc\\SMBUS_Test\\SmIoDriver\\x64\\Release\\SmIoDriver.pdb"
        $str1 = "\\DosDevices\\SparkIO" wide
        $serial = { 33 00 00 00 6D 9D A5 3E 87 00 9D 33 49 00 00 00 00 00 6D }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $pdb_path and $str1 and $serial
}

