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
| production-rules-linux-v1 | 1.0.89 | 6dff930f5e7f845b9cec2654d97958efdeea42a09cb262a239605b59ccf17533 |
| production-rules-macos-v1 | 1.0.89 | 1d41c3f24444f9ad83da397760cdfc089427fd27f9287868ac64cba02661689f |
| production-rules-windows-v1 | 1.0.89 | f046accb6301179f42ac8569c707f451a8d84e59115ae0b6cd5b1594f703a676 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.89', '1.0.88') by OS/MITRE Tactic.
| Tactic      |   Windows |   Linux |   macOS |   Total by Tactic |
|-------------|-----------|---------|---------|-------------------|
| Execution   |         1 |       0 |       0 |                 1 |
| Total by OS |         1 |       0 |       0 |                 1 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        10 |       0 |       8 |                18 |
| Command and Control  |        33 |      12 |      37 |                82 |
| Credential Access    |        46 |       4 |      29 |                79 |
| Defense Evasion      |       262 |      47 |      53 |               362 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        85 |      41 |      79 |               205 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        54 |       1 |       2 |                57 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      32 |      22 |               110 |
| Privilege Escalation |        67 |       8 |       8 |                83 |
| Total by OS          |       650 |     153 |     246 |              1049 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
