rule Windows_Trojan_OtterCookie_3e1bceb3 {
    meta:
        author = "Elastic Security"
        id = "3e1bceb3-317f-4a02-a276-839cfd0d8410"
        fingerprint = "6eba2bf2ea5febcec6f2690f78cabee34fd7b211f63654aa6b83d1da5a2792a4"
        creation_date = "2026-07-13"
        last_modified = "2026-07-15"
        threat_name = "Windows.Trojan.OtterCookie"
        reference_sample = "95bb3d2abd08108f7ed9a61cc8493ab3259cabf1b5a21073c75d89dac8f61c49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "|vmware|virtualbox|qemu|kvm|xen|parallels|bochs" ascii wide
        $b = "/api/service/process/" ascii wide
        $c = "npm install socket.io-client --save --no-warnings --no-save --no-progress --loglevel silent"
        $d = "messge" ascii wide
        $e = "whoIm" ascii wide
        $f = "/api/service/makelog" ascii wide
    condition:
        5 of them
}

rule Windows_Trojan_OtterCookie_ae33e607 {
    meta:
        author = "Elastic Security"
        id = "ae33e607-5ed5-4259-9a51-dd011f911b11"
        fingerprint = "e1148316c1e21444352e4683d650eac6b36e1d0e9a3da448895c8a59bb33f65d"
        creation_date = "2026-07-13"
        last_modified = "2026-07-15"
        threat_name = "Windows.Trojan.OtterCookie"
        reference_sample = "b8a4d8bf5912df9435e3fa98cfff0fb4b2c38cff1bb4eda3ef632db8c729aa15"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "isFile" ascii wide
        $b = "isDirectory" ascii wide
        $c = "wmic logicaldisk get name" ascii wide
        $d = "excludeFolders" ascii wide
        $e = "else await scanDir(rootDir)" ascii wide
    condition:
        4 of them
}

