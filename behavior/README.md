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
| production-rules-linux-v1 | 1.0.93 | 938e5d8a1dfec55441ec4f3a12581feef7d6b03add03555242c7b731d6264535 |
| production-rules-macos-v1 | 1.0.93 | b37a0bdc24cef77cd152fe2ebf6e229aacdf4e9534ee781017bac9deed81ce10 |
| production-rules-windows-v1 | 1.0.93 | 70afa22e96cf6d4a2c616cad8fbb500ced450ae51932da2c75119ee97c0bb003 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.93', '1.0.92') by OS/MITRE Tactic.

No rule updates have been made between versions 1.0.93 and 1.0.92

Note: Latest Total Production Rules by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         9 |       0 |       8 |                17 |
| Command and Control  |        33 |      13 |      37 |                83 |
| Credential Access    |        46 |       4 |      30 |                80 |
| Defense Evasion      |       274 |      49 |      53 |               376 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        88 |      46 |      79 |               213 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        55 |       1 |       2 |                58 |
| Lateral Movement     |        10 |       1 |       1 |                12 |
| Persistence          |        56 |      34 |      23 |               113 |
| Privilege Escalation |        66 |       9 |       8 |                83 |
| Total by OS          |       662 |     164 |     248 |              1074 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
