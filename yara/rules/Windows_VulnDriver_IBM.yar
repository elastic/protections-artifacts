rule Windows_VulnDriver_IBM_7be3f2be {
    meta:
        author = "Elastic Security"
        id = "7be3f2be-73fe-4b14-b7f8-5f32216e81b2"
        fingerprint = "45e723c54343c10c29639cb6722194c430f0dfc3918370218bd89a96b9f881be"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IBM Polska Sp. z o.o."
        threat_name = "Windows.VulnDriver.IBM"
        reference_sample = "1c8dfa14888bb58848b4792fb1d8a921976a9463be8334cff45cc96f1276049a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 42 4D 20 50 6F 6C 73 6B 61 20 53 70 2E 20 7A 20 6F 2E 6F 2E }
        $str1 = "CITMDRV_IA64.pdb"
        $str2 = "IOCTL_MAP_MEM"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

rule Windows_VulnDriver_IBM_b11e0995 {
    meta:
        author = "Elastic Security"
        id = "b11e0995-1631-4fee-8782-8eafce30f2fd"
        fingerprint = "e7b7a529945b9a09c2f16a2f37e4da6c6f2b8d51e4d01cbc42a182f74b29b0ca"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IBM Polska Sp. z o.o."
        threat_name = "Windows.VulnDriver.IBM"
        reference_sample = "29e0062a017a93b2f2f5207a608a96df4d554c5de976bd0276c2590a03bd3e94"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 42 4D 20 50 6F 6C 73 6B 61 20 53 70 2E 20 7A 20 6F 2E 6F 2E }
        $str1 = "CITMDRV_AMD64.pdb"
        $str2 = "IOCTL_MAP_MEM"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

rule Windows_VulnDriver_IBM_496c3bda {
    meta:
        author = "Elastic Security"
        id = "496c3bda-b158-4747-84c3-f0464add6149"
        fingerprint = "bf57ebf0d4eec2c388911433c826d8f48b8a751cac4f6abfa3f8ff652a7ca30f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IBM"
        threat_name = "Windows.VulnDriver.IBM"
        reference_sample = "dba8db472e51edd59f0bbaf4e09df71613d4dd26fd05f14a9bc7e3fc217a78aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 42 4D }
        $str1 = "sysconp.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

