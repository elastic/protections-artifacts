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
| production-rules-linux-v1 | 1.0.102 | a13427fdd2d8ead88ff3c5b8a6b36d673fda0dd50f38c90831d77142d89e864e |
| production-rules-macos-v1 | 1.0.102 | e9233d4817b2bd8aacb09f8e54bbf3d61fa361c23725540a82de1a9b127c19c5 |
| production-rules-windows-v1 | 1.0.102 | 7785b10274608595b493389a9639e15771dcae3b3563f1ea9d16babe7b8833d7 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.102', '1.0.101') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Credential Access    |         2 |       0 |       1 |                 3 |
| Defense Evasion      |         3 |       0 |       0 |                 3 |
| Execution            |         1 |       1 |       2 |                 4 |
| Initial Access       |         2 |       0 |       0 |                 2 |
| Privilege Escalation |         0 |       1 |       0 |                 1 |
| Total by OS          |         8 |       2 |       3 |                13 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       9 |                20 |
| Command and Control  |        37 |      13 |      41 |                91 |
| Credential Access    |        49 |       4 |      32 |                85 |
| Defense Evasion      |       302 |      50 |      58 |               410 |
| Discovery            |        20 |       1 |       4 |                25 |
| Execution            |        92 |      57 |      94 |               243 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       2 |                14 |
| Persistence          |        57 |      34 |      24 |               115 |
| Privilege Escalation |        69 |      14 |       8 |                91 |
| Total by OS          |       728 |     182 |     277 |              1187 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
