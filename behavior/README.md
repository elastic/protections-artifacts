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
| production-rules-linux-v1 | 1.0.86 | 3030c6c9fe4a388351664f1f7f31967049316363007bc5af8201941af21bc0af |
| production-rules-macos-v1 | 1.0.86 | c4e420367f429720b97eaf1453ba4cd91a7cb2da452c87a90f4312fae749ab6e |
| production-rules-windows-v1 | 1.0.86 | 74ca78bfa079261a603ac11d704c282e4f86631f90df505f949f4b83cb4a1d44 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.86', '1.0.85') by OS/MITRE Tactic.

| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Collection          |         0 |       0 |       1 |                 1 |
| Command and Control |         0 |       0 |       4 |                 4 |
| Credential Access   |         1 |       0 |       0 |                 1 |
| Defense Evasion     |         2 |       0 |       5 |                 7 |
| Execution           |         0 |       0 |       2 |                 2 |
| Total by OS         |         3 |       0 |      12 |                15 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        10 |       0 |       8 |                18 |
| Command and Control  |        33 |      12 |      37 |                82 |
| Credential Access    |        46 |       4 |      29 |                79 |
| Defense Evasion      |       258 |      47 |      53 |               358 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        81 |      42 |      79 |               202 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        54 |       1 |       2 |                57 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      33 |      22 |               111 |
| Privilege Escalation |        67 |       8 |       8 |                83 |
| Total by OS          |       642 |     155 |     246 |              1043 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
