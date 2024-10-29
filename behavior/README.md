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
| production-rules-linux-v1 | 1.0.75 | 451844e80458f42b585e8d9281efcc428b3725443ba85c745ad5bf66f97a44ee |
| production-rules-macos-v1 | 1.0.75 | 118242f07925f45aaf22e7bcc9d202a15c84a303892b1dfeb76f377f65a9a037 |
| production-rules-windows-v1 | 1.0.75 | d1c89a2a0c40d3f3f0d5b20cfa85cefc224441d5be91eb10297c31f1e26ea12f |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.75', '1.0.74') by OS/MITRE Tactic.
| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         1 |       4 |       0 |                 5 |
| Credential Access   |         2 |       1 |       0 |                 3 |
| Defense Evasion     |         6 |      18 |       0 |                24 |
| Execution           |         2 |      13 |       0 |                15 |
| Impact              |         0 |       2 |       0 |                 2 |
| Initial Access      |         1 |       0 |       0 |                 1 |
| Persistence         |         2 |       5 |       0 |                 7 |
| Total by OS         |        14 |      43 |       0 |                57 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        32 |      11 |      27 |                70 |
| Credential Access    |        44 |       4 |      24 |                72 |
| Defense Evasion      |       256 |      42 |      47 |               345 |
| Discovery            |         8 |       1 |       4 |                13 |
| Execution            |        64 |      35 |      70 |               169 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        18 |       4 |       2 |                24 |
| Initial Access       |        53 |       2 |       2 |                57 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        57 |      29 |      17 |               103 |
| Privilege Escalation |        60 |       8 |       8 |                76 |
| Total by OS          |       611 |     137 |     208 |               956 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

