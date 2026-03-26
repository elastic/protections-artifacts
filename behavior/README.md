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
| production-rules-linux-v1 | 1.0.112 | 4eab884619cc9f1cb25b003c97405f504d7cad82205abc31be1d121aff13e127 |
| production-rules-macos-v1 | 1.0.112 | 887411a92bcb71406278c1150a194a86b98fc95e23e36d7f39a96fcee06647a1 |
| production-rules-windows-v1 | 1.0.112 | fb8cdff95519f46b7db1454bcc0567847e811daa88155fdf0f890eb3daae4349 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.112', '1.0.111') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Defense Evasion      |         1 |       0 |       0 |                 1 |
| Execution            |         1 |       1 |       0 |                 2 |
| Privilege Escalation |         2 |       0 |       0 |                 2 |
| Total by OS          |         4 |       1 |       0 |                 5 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       8 |                20 |
| Command and Control  |        39 |      11 |      42 |                92 |
| Credential Access    |        52 |       7 |      34 |                93 |
| Defense Evasion      |       320 |      44 |      59 |               423 |
| Discovery            |        20 |       1 |       1 |                22 |
| Execution            |        94 |      58 |     103 |               255 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        60 |      25 |      20 |               105 |
| Privilege Escalation |        73 |      14 |       9 |                96 |
| Total by OS          |       761 |     169 |     283 |              1213 |
