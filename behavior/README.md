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
| production-rules-linux-v1 | 1.0.47 | f97ef103ae0c38e9c31d3291cd20cf44b2426dae6c1a979939585f62d12573ba |
| production-rules-macos-v1 | 1.0.47 | caff0dbf15dd20051bcc9b051d4bebe5e2588e96e76a560415dcd7941ae76757 |
| production-rules-windows-v1 | 1.0.47 | be788888a04e9fe92590d86cfc9b4dd4ca4da29ea75a6259b537edb1136e861b |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.47', '1.0.44') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         4 |       0 |       0 |                 4 |
| Command and Control  |         1 |       0 |       1 |                 2 |
| Defense Evasion      |        16 |       5 |       2 |                23 |
| Discovery            |         0 |       0 |       1 |                 1 |
| Execution            |         4 |       0 |       3 |                 7 |
| Initial Access       |         1 |       0 |       0 |                 1 |
| Persistence          |         2 |       1 |       0 |                 3 |
| Privilege Escalation |         2 |       2 |       0 |                 4 |
| Total by OS          |        30 |       8 |       7 |                45 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         5 |       0 |       0 |                 5 |
| Command and Control  |        23 |       2 |      17 |                42 |
| Credential Access    |        36 |       0 |      11 |                47 |
| Defense Evasion      |       171 |       7 |      34 |               212 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        49 |       5 |      32 |                86 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        45 |       1 |       2 |                48 |
| Lateral Movement     |         7 |       0 |       1 |                 8 |
| Persistence          |        47 |       1 |      14 |                62 |
| Privilege Escalation |        46 |       4 |       7 |                57 |
| Total by OS          |       447 |      22 |     124 |               593 |
