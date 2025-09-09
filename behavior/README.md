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
| production-rules-linux-v1 | 1.0.97 | 0c020a0f252dbbf7808d46ab3f5eb8759ad567512b457dd184f27b535a424286 |
| production-rules-macos-v1 | 1.0.97 | d590b982398bb6e196f3349a9eda8802bc2e4dc8fb1435ba60a9b7c9e32f503a |
| production-rules-windows-v1 | 1.0.97 | d8a4dd1f68d4678b0e3ab3d1b48d16b5db79818b6ecc501b9c0b6e867d3b1401 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.97', '1.0.96') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         0 |       0 |       1 |                 1 |
| Command and Control  |         0 |       1 |       0 |                 1 |
| Defense Evasion      |         0 |       1 |       3 |                 4 |
| Execution            |         0 |       7 |       5 |                12 |
| Lateral Movement     |         0 |       1 |       0 |                 1 |
| Persistence          |         0 |       0 |       2 |                 2 |
| Privilege Escalation |         0 |       4 |       0 |                 4 |
| Total by OS          |         0 |      14 |      11 |                25 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       9 |                20 |
| Command and Control  |        37 |      14 |      39 |                90 |
| Credential Access    |        46 |       4 |      30 |                80 |
| Defense Evasion      |       294 |      50 |      57 |               401 |
| Discovery            |         7 |       1 |       4 |                12 |
| Execution            |        88 |      53 |      88 |               229 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        59 |       1 |       2 |                62 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        57 |      34 |      25 |               116 |
| Privilege Escalation |        68 |      13 |       8 |                89 |
| Total by OS          |       695 |     178 |     267 |              1140 |

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
