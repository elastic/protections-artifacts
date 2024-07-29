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
| production-rules-linux-v1 | 1.0.66 | 3053a6c8c16342854788e87ab2c84532381b328c9a4928331ddc39654bae97df |
| production-rules-macos-v1 | 1.0.66 | bb09703252f9d448bc062af8e3653aa8cf4b10be0007d2595ed1ff8daf1a1602 |
| production-rules-windows-v1 | 1.0.66 | 9d4c14e65c3bffb2aadbfa23fadd318c4310c5d2f9a96e708fdb91f8e4e525db |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.66', '1.0.65') by OS/MITRE Tactic.
| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         1 |       0 |       0 |                 1 |
| Credential Access   |         1 |       0 |       1 |                 2 |
| Defense Evasion     |         8 |       0 |       0 |                 8 |
| Discovery           |         1 |       0 |       1 |                 2 |
| Persistence         |         1 |       0 |       0 |                 1 |
| Total by OS         |        12 |       0 |       2 |                14 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       3 |                14 |
| Command and Control  |        31 |       4 |      26 |                61 |
| Credential Access    |        42 |       3 |      22 |                67 |
| Defense Evasion      |       239 |      15 |      38 |               292 |
| Discovery            |         6 |       0 |       4 |                10 |
| Execution            |        61 |      14 |      59 |               134 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        49 |       2 |       2 |                53 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        53 |       3 |      17 |                73 |
| Privilege Escalation |        58 |       7 |       8 |                73 |
| Total by OS          |       575 |      51 |     183 |               809 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

