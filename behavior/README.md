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
| production-rules-linux-v1 | 1.0.110 | 3190c1f7f9c9586aa12b5455936e41989458c358958be4e7d990a896bb6d8282 |
| production-rules-macos-v1 | 1.0.110 | a3198c3642e217f5f6987b8d91df9353245d22a7745fa05ee14581f3f2d2932f |
| production-rules-windows-v1 | 1.0.110 | 82ebf4a116e4e49336fde578d75babd1349a747edb4dfca6b452b00e9b01d48f |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.110', '1.0.109') by OS/MITRE Tactic.

| Tactic          |   Windows |   Linux |   macOS |   Total by Tactic |
|-----------------|-----------|---------|---------|-------------------|
| Collection      |         0 |       0 |       1 |                 1 |
| Defense Evasion |         0 |       0 |       1 |                 1 |
| Execution       |         0 |       0 |       1 |                 1 |
| Total by OS     |         0 |       0 |       3 |                 3 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       8 |                20 |
| Command and Control  |        39 |       9 |      41 |                89 |
| Credential Access    |        52 |       7 |      34 |                93 |
| Defense Evasion      |       319 |      43 |      59 |               421 |
| Discovery            |        20 |       1 |       1 |                22 |
| Execution            |        93 |      53 |     103 |               249 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       0 |       2 |                64 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        60 |      25 |      20 |               105 |
| Privilege Escalation |        71 |      14 |       9 |                94 |
| Total by OS          |       757 |     160 |     282 |              1199 |
