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
| production-rules-linux-v1 | 1.0.91 | 615f28962abdfd8f16df23dbe1f8b8c4ab06959d4c21205a425960fa47cd138b |
| production-rules-macos-v1 | 1.0.91 | d1ca2d60edf091196c0ad0a4a91a661bb53e5f3cd9d8f715aededb473f7576cc |
| production-rules-windows-v1 | 1.0.91 | a58ae027665e6d6b96f779dc403c2a1f1d3b9953d2dbaa50ce5ba56b05a5e404 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.92', '1.0.91') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         0 |       0 |       1 |                 1 |
| Credential Access    |         0 |       0 |       1 |                 1 |
| Defense Evasion      |         7 |       0 |       0 |                 7 |
| Execution            |         2 |       3 |       0 |                 5 |
| Persistence          |         0 |       0 |       1 |                 1 |
| Privilege Escalation |         0 |       1 |       0 |                 1 |
| Total by OS          |         9 |       4 |       3 |                16 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        10 |       0 |       8 |                18 |
| Command and Control  |        33 |      12 |      37 |                82 |
| Credential Access    |        46 |       4 |      30 |                80 |
| Defense Evasion      |       274 |      47 |      53 |               374 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        88 |      46 |      79 |               213 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        55 |       1 |       2 |                58 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      34 |      23 |               113 |
| Privilege Escalation |        66 |       9 |       8 |                83 |
| Total by OS          |       664 |     161 |     248 |              1073 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
