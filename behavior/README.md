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
| production-rules-linux-v1 | 1.0.65 | 304d3743d4213e176a8750af40cb7a8073c86b35b665a651064b4ccbc6a90d42 |
| production-rules-macos-v1 | 1.0.65 | f05688350b90208ede2407b75e34c53d40894b17e5b27260fe36a628a27f7110 |
| production-rules-windows-v1 | 1.0.65 | d615178933219e8c53fab9a4c6bb72dd4e1459466c5b9c22a4ecd4db6d236a75 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.65', '1.0.64') by OS/MITRE Tactic.
| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         0 |       1 |       1 |                 2 |
| Defense Evasion      |         4 |       7 |       2 |                13 |
| Execution            |         1 |       6 |       5 |                12 |
| Initial Access       |         0 |       1 |       0 |                 1 |
| Persistence          |         0 |       1 |       0 |                 1 |
| Privilege Escalation |         0 |       2 |       0 |                 2 |
| Total by OS          |         5 |      18 |       8 |                31 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       3 |                14 |
| Command and Control  |        31 |       4 |      26 |                61 |
| Credential Access    |        41 |       3 |      21 |                65 |
| Defense Evasion      |       231 |      15 |      38 |               284 |
| Discovery            |         5 |       0 |       3 |                 8 |
| Execution            |        61 |      16 |      59 |               136 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        49 |       2 |       2 |                53 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        52 |       3 |      17 |                72 |
| Privilege Escalation |        58 |       7 |       8 |                73 |
| Total by OS          |       564 |      53 |     181 |               798 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

