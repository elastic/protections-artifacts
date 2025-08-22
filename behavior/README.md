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
| production-rules-linux-v1 | 1.0.95 | da2937e53edfc4ba859827b8f1dbb5f1e6b8b904147e25473caf134a97ec9693 |
| production-rules-macos-v1 | 1.0.95 | ef9bfd4d056d30265f8a2103e12e75f8f4048b7f3a2ed817b149b958b6fa2421 |
| production-rules-windows-v1 | 1.0.95 | 3cd2223a81aeb28d8327b92658a4e769a909a6b674714030c7f6290cd66d5195 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.95', '1.0.94') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         1 |       0 |       2 |                 3 |
| Defense Evasion      |         7 |       0 |       4 |                11 |
| Execution            |         0 |       0 |       5 |                 5 |
| Initial Access       |         1 |       0 |       0 |                 1 |
| Lateral Movement     |         0 |       0 |       1 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |        10 |       0 |      12 |                22 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         9 |       0 |       8 |                17 |
| Command and Control  |        34 |      13 |      38 |                85 |
| Credential Access    |        46 |       4 |      30 |                80 |
| Defense Evasion      |       281 |      49 |      55 |               385 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        88 |      46 |      83 |               217 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        56 |       1 |       2 |                59 |
| Lateral Movement     |        10 |       1 |       2 |                13 |
| Persistence          |        56 |      34 |      23 |               113 |
| Privilege Escalation |        67 |       9 |       8 |                84 |
| Total by OS          |       672 |     164 |     256 |              1092 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
