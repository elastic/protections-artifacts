## Elastic Security Malicious Behavior Protection Rules

Prebuilt high signal [EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) rules that runs on the endpoint to disrupt malicious behavior, this layer of prevention equips Elastic Agent to protect Linux, Windows, and macOS hosts from a broad range of attack techniques with a major focus on the following tactics :

- [Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [Execution](https://attack.mitre.org/tactics/TA0002/)
- [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [Impact](https://attack.mitre.org/tactics/TA0040/)

Prevention is achieved by pairing post-execution analytics with response actions to kill a specific process or a full process tree tailored to stop the adversary at the initial stages of the attack. Each protection rule is mapped to the most relevant [MITRE ATT&CK](https://attack.mitre.org/) tactic,  technique and subtechnique.

The true positive rate that we aim to maintain is at least 70%, thus we prioritize analytics logic precision to reduce detection scope via prevention.

Another example of our commitment to openness in security is our existing public [Detection Rules](https://github.com/elastic/detection-rules) repository where we share [EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) rules that run on the SIEM side, and that have a broader detection logic which make them more suitable for detection and hunting.


### Latest Release

| artifact             | version        | hash            |
| -------------------- | -------------- | --------------- |
| production-rules-linux-v1 | 1.0.108 | 13ad889fc65e6d4a37eddb3ffe56b12196ce42d1979666c581e1448bfcd55967 |
| production-rules-macos-v1 | 1.0.108 | 4e62ac061765fe140d0bef75e1810cb66df39a548221ada3127ee69f43c13bf8 |
| production-rules-windows-v1 | 1.0.108 | 53f879f89b1f604d250330712031145200dcf701062827f9dc2bbccee4ad3fcd |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.108', '1.0.106') by OS/MITRE Tactic.

No rule updates have been made between versions 1.0.108 and 1.0.106

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       7 |                19 |
| Command and Control  |        39 |      15 |      42 |                96 |
| Credential Access    |        52 |       7 |      34 |                93 |
| Defense Evasion      |       319 |      51 |      61 |               431 |
| Discovery            |        20 |       2 |       1 |                23 |
| Execution            |        93 |      70 |     104 |               267 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        60 |      34 |      20 |               114 |
| Privilege Escalation |        71 |      16 |       9 |                96 |
| Total by OS          |       757 |     204 |     285 |              1246 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
