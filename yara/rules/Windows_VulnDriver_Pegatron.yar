rule Windows_VulnDriver_Pegatron_f411086c {
    meta:
        author = "Elastic Security"
        id = "f411086c-6a26-432f-b46f-cf3a9fc82ec2"
        fingerprint = "b1adc33ddfe6de98a98061f7d1e512b6494f70e4acf72bec6a3108df6690cb39"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PEGATRON CORPORATION"
        threat_name = "Windows.VulnDriver.Pegatron"
        reference_sample = "1076504a145810dfe331324007569b95d0310ac1e08951077ac3baf668b2a486"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 45 47 41 54 52 4F 4E 20 43 4F 52 50 4F 52 41 54 49 4F 4E }
        $str1 = "TdeIo64.pdb"
        $str2 = "IOCTL_INDEXIO_WRITE_DWORD"
        $str3 = "IOCTL_INDEXIO_READ_DWORD"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Pegatron_cb69cf04 {
    meta:
        author = "Elastic Security"
        id = "cb69cf04-e6c9-46af-8b6e-03a14c4dfcd4"
        fingerprint = "6aac52ef287ed9d57df37b1a1d479ffb9ea4cc6361f85170a7f59aee4f67ef6b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PEGATRON CORPORATION"
        threat_name = "Windows.VulnDriver.Pegatron"
        reference_sample = "aa282c3b989a0eca78023347b7b1e1feef7e42edf9fd2bef5d55c66000c99911"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 45 47 41 54 52 4F 4E 20 43 4F 52 50 4F 52 41 54 49 4F 4E }
        $str1 = "TdeIo.pdb"
        $str2 = "IOCTL_INDEXIO_WRITE_DWORD"
        $str3 = "IOCTL_INDEX_DATA_IO_WRITE"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

