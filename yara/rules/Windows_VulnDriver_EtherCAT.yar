rule Windows_VulnDriver_EtherCAT_e5b6e70d {
    meta:
        author = "Elastic Security"
        id = "e5b6e70d-61b8-4ec3-a4e1-e3f942b92d60"
        fingerprint = "d0c6ca8ab26b964ae866dda1081087e59ae99af6958ad7045ffdc29614f490b8"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.VulnDriver.EtherCAT"
        reference_sample = "8001d7161d662a6f4afb4d17823144e042fd24696d8904380d48065209f28258"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "c:\\fz-corera\\fz-corera.610\\fh-driver\\fh-ethercat_dio\\objchk_win7_x86\\i386\\FH-EtherCAT_DIO.pdb"
        $seq1 = { BA 4E 00 00 00 B0 87 EE BA 4E 00 00 00 B0 87 EE BA 4E 00 00 00 B0 07 EE BA 4F 00 00 00 B0 07 EE BA 4E 00 00 00 }
        $seq2 = { 83 C1 24 8B 55 FC 89 8A 24 10 00 00 8B 45 FC 83 C0 24 8B 4D FC 89 81 28 10 00 00 8B 55 FC C7 82 2C 10 00 00 00 00 00 00 8B 45 FC }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and $seq1 and $seq2
}

