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
| production-rules-linux-v1 | 1.0.88 | 1f0f694dfd5367fa4c61f0f86fcfd5790cea29b58e606dc16e7a3105d6c02ff2 |
| production-rules-macos-v1 | 1.0.88 | b6939b4ebc2179a551c0966161474810396b7ee3c85f5e7f2d750cd3cd9fe0b7 |
| production-rules-windows-v1 | 1.0.88 | cc8e2858dee0f24f053af1480d1b37e6d8acfd68e287e75cb8e6ed08200079e2 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.88', '1.0.87') by OS/MITRE Tactic.
| Tactic          |   Windows |   Linux |   macOS |   Total by Tactic |
|-----------------|-----------|---------|---------|-------------------|
| Defense Evasion |         4 |       0 |       0 |                 4 |
| Execution       |         3 |       0 |       0 |                 3 |
| Total by OS     |         7 |       0 |       0 |                 7 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        10 |       0 |       8 |                18 |
| Command and Control  |        33 |      12 |      37 |                82 |
| Credential Access    |        46 |       4 |      29 |                79 |
| Defense Evasion      |       262 |      47 |      53 |               362 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        84 |      41 |      79 |               204 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        54 |       1 |       2 |                57 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      32 |      22 |               110 |
| Privilege Escalation |        67 |       8 |       8 |                83 |
| Total by OS          |       649 |     153 |     246 |              1048 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
