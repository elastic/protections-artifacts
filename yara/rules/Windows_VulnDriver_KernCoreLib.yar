rule Windows_VulnDriver_KernCoreLib_16c13fc9 {
    meta:
        author = "Elastic Security"
        id = "16c13fc9-a06c-4e6e-aa8b-58d8431846cf"
        fingerprint = "e11d49cdda0e4ee85a2dfe74ca22ee0b7a729851415e777380efc7fb0fd88df3"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: WDKTestCert test,133636665677602039"
        threat_name = "Windows.VulnDriver.KernCoreLib"
        reference_sample = "7196cc5f4259d53f0badbc56d4d27ec39e13a622ae4dd34d99a0b2248a6d653b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 74 65 73 74 2C 31 33 33 36 33 36 36 36 35 36 37 37 36 30 32 30 33 39 }
        $str1 = "C:\\Users\\test\\Desktop\\WinIo_KernCoreLib\\WinIo_KernCoreLib\\WinIo\\x64\\Debug\\KernCoreLib64.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

