rule Windows_VulnDriver_Driverinject_3075aeb4 {
    meta:
        author = "Elastic Security"
        id = "3075aeb4-3712-443d-8657-e8ed71d583fb"
        fingerprint = "5d5011e13065fbd7f796bed8354fe93b3ac15a8d6615694c6ede34fd97c0218c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 北京汇聚四海商贸有限公司"
        threat_name = "Windows.VulnDriver.Driverinject"
        reference_sample = "30061ef383e18e74bb067fbca69544f1a7544e8dc017d4e7633d8379aff4c3c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 8C 97 E4 BA AC E6 B1 87 E8 81 9A E5 9B 9B E6 B5 B7 E5 95 86 E8 B4 B8 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "RedDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

