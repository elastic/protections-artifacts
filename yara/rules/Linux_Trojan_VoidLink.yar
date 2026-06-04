rule Linux_Trojan_VoidLink_0868fa9d {
    meta:
        author = "Elastic Security"
        id = "0868fa9d-e89d-402d-b865-010903a54bab"
        fingerprint = "975eb15ea5558cbd2eb55f201310123447ab1284954818498b6596fae5dc0f68"
        creation_date = "2026-01-15"
        last_modified = "2026-03-10"
        description = "Detects the VoidLink Beacon"
        threat_name = "Linux.Trojan.VoidLink"
        reference_sample = "05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_vl_a = "vl_stealth.ko"
        $str_vl_b = "vl_ss_loader"
        $str_vl_c = "sd_ss_loader"
        $str_beacon_1 = "beacon_truncate"
        $str_beacon_2 = "beacon_exec"
        $str_beacon_3 = "beacon_readlink"
        $str_beacon_4 = "beacon_file_read"
        $str_f = "VoidLink"
    condition:
        1 of ($str_vl_*) or 2 of ($str_beacon_*) and $str_f
}

rule Linux_Trojan_VoidLink_e4c13c2c {
    meta:
        author = "Elastic Security"
        id = "e4c13c2c-2813-4942-93a1-1bed72ad3c7d"
        fingerprint = "246e070f045575cf044eb20607001cac3f8a1704ee71bd052ac9d2bc231fd406"
        creation_date = "2026-01-15"
        last_modified = "2026-03-10"
        description = "Detects the VoidLink Plugins"
        threat_name = "Linux.Trojan.VoidLink"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $name = "VoidLink"
        $str_b = "BeaconAPI_v3"
        $str_c = "[PLUGIN_EXEC]"
        $str_d = "parallel_executed"
        $str_e = "[ChainExecutor]"
        $str_f = "[PARSE_SHDR]"
        $str_g = "ShellcodeTimeout"
        $str_h = "camouflage executor"
        $str_i = "anti-reverse executor"
    condition:
        $name and 5 of ($str_*)
}

