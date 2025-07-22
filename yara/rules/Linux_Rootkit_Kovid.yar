rule Linux_Rootkit_Kovid_b77dc7f4 {
  meta:
    author           = "Elastic Security"
    id               = "b77dc7f4-fef1-4256-ac34-677ad1c5b618"
    fingerprint      = "29ae4fc448eb746b7d6ec192befd03977e83a1ad5b4d1369621d6d42b482ae50"
    creation_date    = "2024-11-13"
    last_modified    = "2024-11-22"
    threat_name      = "Linux.Rootkit.Kovid"
    reference_sample = "933273ff95a57dfe0162175dc6143395e23c69e36d8ca366481b795deaab4fd0"
    severity         = 100
    arch_context     = "x86, arm64"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $str1  = "name=kovid"
    $str2  = "kovid.ko"
    $str3  = "dontblink"
    $str4  = "author=whatever coorp"
    $str5  = "Your module 'unhide' magic word is: '%s'"
    $str6  = ".sshd_orig"
    $str7  = ".lm.sh"
    $str8  = ".kv.ko"
    $str9  = "whitenose"
    $str10 = "pinknose"
    $str11 = "rednose"
    $str12 = "blacknose"
    $str13 = "greynose"
    $str14 = "purplenose"
    $str15 = "fh_remove_hook"
    $str16 = "backdoor can only be unhidden either by exit or rmmod: %d"
    $str17 = "get_unhide_magic_word"
    $str18 = "invalid data: syscall hook setreuid will not work"
    $str19 = "Fuck-off"
    $str20 = "/KoviD/src/sys.c"
    $func1 = "kv_find_hidden_task"
    $func2 = "kv_for_each_hidden_backdoor_data"
    $func3 = "kv_bd_search_iph_source"
    $func4 = "kv_check_cursing"
    $func5 = "kv_for_each_hidden_backdoor_task"
    $func6 = "kv_find_hidden_pid"
    $func7 = "kv_hide_task_by_pid"
    $func8 = "kv_unhide_task_by_pid_exit_group"
    $func9 = "kv_util_random_AZ_string"

  condition:
    4 of ($str*) or 4 of ($func*)
}

