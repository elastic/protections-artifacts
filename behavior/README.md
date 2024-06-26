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
| production-rules-linux-v1 | 1.0.64 | 046a82cef977534690088995d0ddcaec66004a19d58f29d0f5ed6d77d2ac3312 |
| production-rules-macos-v1 | 1.0.64 | 7bd9ea30aa5bc14a51005341eb8e8d42ba274d77319d889c755f4e078cec2020 |
| production-rules-windows-v1 | 1.0.64 | 8d801b8519e670c0343c90420c02d8061d0d015a9556c5a09fb14004a25b58eb |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.64', '1.0.63') by OS/MITRE Tactic.
| Tactic            |   Windows |   Linux |   macOS |   Total by Tactic |
|-------------------|-----------|---------|---------|-------------------|
| Credential Access |         9 |       0 |       0 |                 9 |
| Defense Evasion   |         6 |       0 |       0 |                 6 |
| Discovery         |         1 |       0 |       0 |                 1 |
| Execution         |         4 |       0 |       0 |                 4 |
| Impact            |         3 |       0 |       0 |                 3 |
| Total by OS       |        23 |       0 |       0 |                23 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       3 |                14 |
| Command and Control  |        31 |       3 |      25 |                59 |
| Credential Access    |        41 |       3 |      21 |                65 |
| Defense Evasion      |       227 |       9 |      36 |               272 |
| Discovery            |         5 |       0 |       3 |                 8 |
| Execution            |        60 |      10 |      54 |               124 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        49 |       1 |       2 |                52 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        52 |       2 |      17 |                71 |
| Privilege Escalation |        58 |       5 |       8 |                71 |
| Total by OS          |       559 |      36 |     173 |               768 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

