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
| production-rules-linux-v1 | 1.0.58 | e3d74985e44498f385ab23c6a48a97b99667acc049276bc77b687094f5f6b25a |
| production-rules-macos-v1 | 1.0.58 | c556379458d04667f0829bafbd51ab303ce9e2bd2979b7ab796d7cc7109c0229 |
| production-rules-windows-v1 | 1.0.58 | 91a41f4fb2830ce417e931003e852cdbf370f82a2df4aa8c4160308c94a96f42 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.58', '1.0.57') by OS/MITRE Tactic.
| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Collection          |         3 |       0 |       0 |                 3 |
| Command and Control |         2 |       0 |       0 |                 2 |
| Defense Evasion     |         2 |       0 |       0 |                 2 |
| Execution           |         2 |       0 |       0 |                 2 |
| Initial Access      |         3 |       0 |       0 |                 3 |
| Total by OS         |        12 |       0 |       0 |                12 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         8 |       0 |       2 |                10 |
| Command and Control  |        26 |       3 |      26 |                55 |
| Credential Access    |        37 |       3 |      20 |                60 |
| Defense Evasion      |       209 |       9 |      38 |               256 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        54 |      10 |      46 |               110 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        48 |       1 |       2 |                51 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        51 |       2 |      18 |                71 |
| Privilege Escalation |        57 |       5 |       8 |                70 |
| Total by OS          |       516 |      36 |     167 |               719 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

