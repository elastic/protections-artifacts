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
| production-rules-linux-v1 | 1.0.84 | 4b4d60592c21f15232829c32b7de8a7020f3558ebe7e384163a93a3ccf15ce53 |
| production-rules-macos-v1 | 1.0.84 | e6c963d218ab1685ce382ab84a44379169d48d2d384a5c41c0ee6a842eaa5a6e |
| production-rules-windows-v1 | 1.0.84 | 5536bdee3280d4b4444439212863c5285ef8e7dfd595ac52f40c533b3d859d66 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.84', '1.0.83') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         0 |       0 |       1 |                 1 |
| Command and Control  |         0 |       0 |       5 |                 5 |
| Credential Access    |         0 |       0 |       3 |                 3 |
| Defense Evasion      |         4 |       0 |       2 |                 6 |
| Execution            |         1 |       0 |       0 |                 1 |
| Persistence          |         0 |       3 |       1 |                 4 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |         6 |       3 |      12 |                21 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       7 |                19 |
| Command and Control  |        34 |      13 |      33 |                80 |
| Credential Access    |        46 |       4 |      27 |                77 |
| Defense Evasion      |       279 |      52 |      48 |               379 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        85 |      43 |      73 |               201 |
| Exfiltration         |         0 |       1 |       1 |                 2 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        54 |       2 |       2 |                58 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      35 |      21 |               112 |
| Privilege Escalation |        66 |       8 |       8 |                82 |
| Total by OS          |       669 |     166 |     227 |              1062 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
