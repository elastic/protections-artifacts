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
| production-rules-linux-v1 | 1.0.85 | efac35ba6a233ffc0351ac6eb1d220ade8ef2efe59b06d2aa7910968482c0a9b |
| production-rules-macos-v1 | 1.0.85 | 32497d0fe8f1ab829fa829c8078ca256d7e617e9815fc5a997348da049b84509 |
| production-rules-windows-v1 | 1.0.85 | 3a01116485c13a88b1cb3d883af0dba0684e27afbcc95b7916a37ba1510291e4 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.85', '1.0.84') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Credential Access    |         0 |       0 |       2 |                 2 |
| Defense Evasion      |         4 |       0 |       0 |                 4 |
| Execution            |         1 |       0 |       4 |                 5 |
| Persistence          |         0 |       0 |       1 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |         6 |       0 |       7 |                13 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       7 |                19 |
| Command and Control  |        34 |      13 |      33 |                80 |
| Credential Access    |        46 |       4 |      29 |                79 |
| Defense Evasion      |       283 |      52 |      48 |               383 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        86 |      43 |      77 |               206 |
| Exfiltration         |         0 |       1 |       1 |                 2 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        54 |       2 |       2 |                58 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      35 |      22 |               113 |
| Privilege Escalation |        67 |       8 |       8 |                83 |
| Total by OS          |       675 |     166 |     234 |              1075 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
