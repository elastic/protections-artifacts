rule Linux_Trojan_Kaiji_253c44de {
    meta:
        author = "Elastic Security"
        id = "253c44de-3f48-49f9-998d-1dec2981108c"
        fingerprint = "f390a16ca4270dc38ce1a52bbdc1ac57155f369a74005ff2a4e46c6d043b869e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "e31eb8880bb084b4c642eba127e64ce99435ea8299a98c183a63a2e6a139d926"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EB 27 0F B6 1C 10 48 8B 74 24 40 48 8B BC 24 90 00 00 00 88 }
    condition:
        all of them
}

rule Linux_Trojan_Kaiji_535f07ac {
    meta:
        author = "Elastic Security"
        id = "535f07ac-d727-4866-aaed-74d297a1092c"
        fingerprint = "8853b2a1d5852e436cab2e3402a5ca13839b3cae6fbb56a74b047234b8c1233b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "28b2993d7c8c1d8dfce9cd2206b4a3971d0705fd797b9fde05211686297f6bb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 44 24 10 48 8B 4C 24 08 48 83 7C 24 18 00 74 26 C6 44 24 57 00 48 8B 84 24 98 00 }
    condition:
        all of them
}

