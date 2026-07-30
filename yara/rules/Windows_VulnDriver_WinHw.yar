rule Windows_VulnDriver_WinHw_de58a926 {
    meta:
        author = "Elastic Security"
        id = "de58a926-cda6-47df-892d-2ab378710561"
        fingerprint = "2ea688b42557226eefeb01f7366bbbbffe9c1e1dc0ad0d6b953b6a516ebc5385"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: 广州商科信息科技有限公司"
        threat_name = "Windows.VulnDriver.WinHw"
        reference_sample = "5b204e0a24b5ea67e79329a8c4eb0513cd52a0e7407b99530323fff4c5b59e34"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 B9 BF E5 B7 9E E5 95 86 E7 A7 91 E4 BF A1 E6 81 AF E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "WinHwDriverSys_x64.pdb"
        $str2 = "IOCTL_WHD_GET_DRIVER_VERSION"
        $str3 = "IOCTL_WHD_WRITE_PCI_CONFIG"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

