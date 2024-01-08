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
| production-rules-linux-v1 | 1.0.51 | 91a48556f05fca944c3d4919b0769123acf53362a5e9499bb9331b334f8dbbe3 |
| production-rules-macos-v1 | 1.0.51 | b02b26fd38bed9d8d97e1c03b4ef4e6f453416f751d76c6ffdc55589af826051 |
| production-rules-windows-v1 | 1.0.51 | d366a368862e1957a564497d938160e4da97cc755cd57ffd7782c81dda21b8d9 |


### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.51', '1.0.50') by OS/MITRE Tactic.

| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         0 |       1 |       3 |                 4 |
| Credential Access   |         0 |       2 |       0 |                 2 |
| Execution           |         0 |       0 |       2 |                 2 |
| Persistence         |         0 |       0 |       1 |                 1 |
| Total by OS         |         0 |       3 |       6 |                 9 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         5 |       0 |       1 |                 6 |
| Command and Control  |        24 |       3 |      22 |                49 |
| Credential Access    |        37 |       3 |      18 |                58 |
| Defense Evasion      |       200 |       7 |      36 |               243 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        50 |      10 |      43 |               103 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        45 |       1 |       2 |                48 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        49 |       2 |      17 |                68 |
| Privilege Escalation |        49 |       5 |       7 |                61 |
| Total by OS          |       485 |      34 |     153 |               672 |
