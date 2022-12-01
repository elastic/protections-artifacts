rule Windows_Hacktool_RWEverything_da67eda7 {
    meta:
        author = "Elastic Security"
        id = "da67eda7-1455-4231-8de5-040d5f0dfd6f"
        fingerprint = "078971f0c67b24a7fb321fa64ecfd4e4c3b9785961eea042cc5f9f1cd9e699af"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: ChongKim Chan"
        threat_name = "Windows.Hacktool.RWEverything"
        reference_sample = "d969845ef6acc8e5d3421a7ce7e244f419989710871313b04148f9b322751e5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 6F 6E 67 4B 69 6D 20 43 68 61 6E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

