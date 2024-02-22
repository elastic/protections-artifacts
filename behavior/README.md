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
| production-rules-linux-v1 | 1.0.54 | 49adb2ef4ab456d351c7683396bc23e6d53d3a949743248f1367d1786c01e227 |
| production-rules-macos-v1 | 1.0.54 | 298722cf7c2fd6926a3bdaee717e6e49bd2a0363c49b55fadfbfc37ff675016a |
| production-rules-windows-v1 | 1.0.54 | 81fdada0d44001c2b703b5abc459caf5368016ae4c2ca2a4f2b771667ff4f855 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.53', '1.0.52') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Defense Evasion      |         3 |       0 |       0 |                 3 |
| Execution            |         2 |       0 |       0 |                 2 |
| Initial Access       |         1 |       0 |       0 |                 1 |
| Persistence          |         1 |       0 |       0 |                 1 |
| Privilege Escalation |         2 |       0 |       0 |                 2 |
| Total by OS          |         9 |       0 |       0 |                 9 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         5 |       0 |       1 |                 6 |
| Command and Control  |        24 |       3 |      23 |                50 |
| Credential Access    |        37 |       3 |      19 |                59 |
| Defense Evasion      |       204 |       7 |      37 |               248 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        52 |      10 |      43 |               105 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        45 |       1 |       2 |                48 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        50 |       2 |      17 |                69 |
| Privilege Escalation |        54 |       5 |       7 |                66 |
| Total by OS          |       497 |      34 |     156 |               687 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

