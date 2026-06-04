rule Linux_Rootkit_VoidLink_243306b5 {
    meta:
        author = "Elastic Security"
        id = "243306b5-4c63-4bba-adfb-8b054f2b712b"
        fingerprint = "a159e2089fa61f45af10a1ebca4e9d02dd287e9dfa04f518d630083b9da22e21"
        creation_date = "2026-03-13"
        last_modified = "2026-05-22"
        threat_name = "Linux.Rootkit.VoidLink"
        reference_sample = "8bce8daacaaa546a8fc77f484d776560a28dfb024e3b7aa7c6b322c7c5716ac5"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $mod1 = "AMD Memory Encryption Support"
        $mod2 = "AMD Memory Encryption Driver"
        $mod3 = "Advanced Micro Devices, Inc."
        $func1 = "vl_stealth"
        $func2 = "g_data"
        $func3 = "icmp_cmd"
        $func4 = "chk_pid"
        $func5 = "chk_port"
        $func6 = "mod_hide"
        $func7 = "amd_mem_encrypt"
        $ebpf1 = "hidden_ports"
        $ebpf2 = "recvmsg_ctx"
        $ebpf3 = "SOCK_DIAG_BY_FAMILY"
    condition:
        (2 of ($mod*) and 3 of ($func*)) or (1 of ($mod*) and 2 of ($ebpf*)) or (4 of ($func*))
}

