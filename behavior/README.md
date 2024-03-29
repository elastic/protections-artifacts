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
| production-rules-linux-v1 | 1.0.57 | 5cbafe05e50bb094a27cf7ddf5427196af57f26d6740ef802e7d86f14beb083f |
| production-rules-macos-v1 | 1.0.57 | 0e15792f0b2cae89ac2a12db82d37e4b8a4c279c33e4ed8dc2d5427fe6c90a72 |
| production-rules-windows-v1 | 1.0.57 | 277dd2f4d8533679787ead2eb7b8dac2af5a4febdb515ba86984b74ce7293c6d |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.56', '1.0.55') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         0 |       0 |       1 |                 1 |
| Command and Control  |         0 |       0 |       3 |                 3 |
| Credential Access    |         0 |       0 |       1 |                 1 |
| Defense Evasion      |         0 |       2 |       1 |                 3 |
| Execution            |         0 |       0 |       3 |                 3 |
| Persistence          |         0 |       0 |       1 |                 1 |
| Privilege Escalation |         0 |       0 |       1 |                 1 |
| Total by OS          |         0 |       2 |      11 |                13 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         5 |       0 |       2 |                 7 |
| Command and Control  |        24 |       3 |      26 |                53 |
| Credential Access    |        37 |       3 |      20 |                60 |
| Defense Evasion      |       207 |       9 |      38 |               254 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        52 |      10 |      46 |               108 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        45 |       1 |       2 |                48 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        51 |       2 |      18 |                71 |
| Privilege Escalation |        57 |       5 |       8 |                70 |
| Total by OS          |       504 |      36 |     167 |               707 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

