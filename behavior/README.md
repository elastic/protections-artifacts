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
| production-rules-linux-v1 | 1.0.81 | 8cd535491d05a8769de7c94a3b1cc2a28dbef80c7e27c742f8ce5d43dedac2cc |
| production-rules-macos-v1 | 1.0.81 | b80437ce01b72965c1493c7db4256dc3c69c68ff0f66d07457e604718d251b3d |
| production-rules-windows-v1 | 1.0.81 | 5d347e1282d8b3553489fdb8de945b0f8071685c67822706a94a91997460b13b |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.82', '1.0.81') by OS/MITRE Tactic.

| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         0 |       2 |       0 |                 2 |
| Defense Evasion     |         4 |       9 |       0 |                13 |
| Execution           |         3 |       8 |       0 |                11 |
| Exfiltration        |         0 |       1 |       0 |                 1 |
| Impact              |         0 |       2 |       0 |                 2 |
| Persistence         |         0 |       2 |       0 |                 2 |
| Total by OS         |         7 |      24 |       0 |                31 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       6 |                17 |
| Command and Control  |        34 |      13 |      28 |                75 |
| Credential Access    |        45 |       4 |      24 |                73 |
| Defense Evasion      |       272 |      52 |      46 |               370 |
| Discovery            |         8 |       1 |       5 |                14 |
| Execution            |        70 |      43 |      73 |               186 |
| Exfiltration         |         0 |       1 |       1 |                 2 |
| Impact               |        18 |       6 |       2 |                26 |
| Initial Access       |        54 |       2 |       2 |                58 |
| Lateral Movement     |        11 |       1 |       1 |                13 |
| Persistence          |        56 |      35 |      20 |               111 |
| Privilege Escalation |        65 |       8 |       8 |                81 |
| Total by OS          |       644 |     166 |     216 |              1026 |


### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 
