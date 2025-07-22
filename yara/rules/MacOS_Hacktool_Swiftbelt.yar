rule MacOS_Hacktool_Swiftbelt_bc62ede6 {
  meta:
    author           = "Elastic Security"
    id               = "bc62ede6-e6f1-4c9e-bff2-ef55a5d12ba1"
    fingerprint      = "98d14dba562ad68c8ecc00780ab7ee2ecbe912cd00603fff0eb887df1cd12fdb"
    creation_date    = "2021-10-12"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Hacktool.Swiftbelt"
    reference        = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
    reference_sample = "452c832a17436f61ad5f32ee1c97db05575160105ed1dcd0d3c6db9fb5a9aea1"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $dbg1  = "SwiftBelt/Sources/SwiftBelt"
    $dbg2  = "[-] Firefox places.sqlite database not found for user"
    $dbg3  = "[-] No security products found"
    $dbg4  = "SSH/AWS/gcloud Credentials Search:"
    $dbg5  = "[-] Could not open the Slack Cookies database"
    $sec1  = "[+] Malwarebytes A/V found on this host"
    $sec2  = "[+] Cisco AMP for endpoints found"
    $sec3  = "[+] SentinelOne agent running"
    $sec4  = "[+] Crowdstrike Falcon agent found"
    $sec5  = "[+] FireEye HX agent installed"
    $sec6  = "[+] Little snitch firewall found"
    $sec7  = "[+] ESET A/V installed"
    $sec8  = "[+] Carbon Black OSX Sensor installed"
    $sec9  = "/Library/Little Snitch"
    $sec10 = "/Library/FireEye/xagt"
    $sec11 = "/Library/CS/falcond"
    $sec12 = "/Library/Logs/PaloAltoNetworks/GlobalProtect"
    $sec13 = "/Library/Application Support/Malwarebytes"
    $sec14 = "/usr/local/bin/osqueryi"
    $sec15 = "/Library/Sophos Anti-Virus"
    $sec16 = "/Library/Objective-See/Lulu"
    $sec17 = "com.eset.remoteadministrator.agent"
    $sec18 = "/Applications/CarbonBlack/CbOsxSensorService"
    $sec19 = "/Applications/BlockBlock Helper.app"
    $sec20 = "/Applications/KextViewr.app"

  condition:
    6 of them
}

