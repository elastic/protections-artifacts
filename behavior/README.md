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
| production-rules-linux-v1 | 1.0.96 | aa139fcfa38b3fd0ebe9486da40d9b87c2b93f55cacc1ce08cf2da7b053c50ca |
| production-rules-macos-v1 | 1.0.96 | ee292498a1896f512e2a0c10e5147be72bbb65346993da2e571998b25c9ed518 |
| production-rules-windows-v1 | 1.0.96 | b87205181d3f217e64245b2b794c5814902a463454d6dad9573a2bffedbe2f50 |

### Rules Summary per Tactic

Note: No rule updates have been made between versions 1.0.96 and 1.0.95

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         9 |       0 |       8 |                17 |
| Command and Control  |        34 |      13 |      38 |                85 |
| Credential Access    |        46 |       4 |      30 |                80 |
| Defense Evasion      |       281 |      49 |      54 |               384 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        88 |      46 |      83 |               217 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        56 |       1 |       2 |                59 |
| Lateral Movement     |        10 |       1 |       2 |                13 |
| Persistence          |        56 |      34 |      23 |               113 |
| Privilege Escalation |        67 |       9 |       8 |                84 |
| Total by OS          |       672 |     164 |     255 |              1091 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
