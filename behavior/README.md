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
| production-rules-linux-v1 | 1.0.83 | 6e9b908a039fb7131e919c82b257eba6dfeda5d7d4c08bba79367f61943b9a89 |
| production-rules-macos-v1 | 1.0.83 | b5e1abc486539b4e49af042c8dd6620cad5b82ff05ccdc90c7bea9b2a56282bd |
| production-rules-windows-v1 | 1.0.83 | b7fe3f9fb95c15abc5d2d0b02cb6797b766dd0ec6468159c030006d3380f115c |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.83', '1.0.82') by OS/MITRE Tactic.

| Tactic            |   Windows |   Linux |   macOS |   Total by Tactic |
|-------------------|-----------|---------|---------|-------------------|
| Collection        |         1 |       0 |       0 |                 1 |
| Credential Access |         1 |       0 |       0 |                 1 |
| Defense Evasion   |         3 |       0 |       0 |                 3 |
| Execution         |        14 |       0 |       0 |                14 |
| Total by OS       |        19 |       0 |       0 |                19 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       6 |                18 |
| Command and Control  |        34 |      13 |      28 |                75 |
| Credential Access    |        46 |       4 |      24 |                74 |
| Defense Evasion      |       275 |      52 |      46 |               373 |
| Discovery            |         8 |       1 |       5 |                14 |
| Execution            |        84 |      43 |      73 |               200 |
| Exfiltration         |         0 |       1 |       1 |                 2 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        54 |       2 |       2 |                58 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      32 |      20 |               108 |
| Privilege Escalation |        65 |       8 |       8 |                81 |
| Total by OS          |       663 |     163 |     216 |              1042 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
