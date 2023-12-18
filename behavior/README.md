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
| production-rules-linux-v1 | 1.0.50 | 35d2dfba303f1daad6d05842e9518b9fa9196d60b16f8725a0c02dcb52cb5ea5 |
| production-rules-macos-v1 | 1.0.50 | 457b5516dad4f327cb1b86d39517efc8213818d27249c579588bd1c904e06b85 |
| production-rules-windows-v1 | 1.0.50 | 70c5f97eeb24415ad8b667d2f1056476730ce632cb730b3816ca6f6249edbb76 |


### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.50', '1.0.49') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         0 |       0 |       1 |                 1 |
| Credential Access    |         1 |       0 |       7 |                 8 |
| Defense Evasion      |        12 |       0 |       1 |                13 |
| Execution            |         1 |       0 |       8 |                 9 |
| Initial Access       |         1 |       0 |       0 |                 1 |
| Persistence          |         0 |       0 |       1 |                 1 |
| Privilege Escalation |         1 |       0 |       0 |                 1 |
| Total by OS          |        16 |       0 |      18 |                34 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         5 |       0 |       1 |                 6 |
| Command and Control  |        24 |       2 |      19 |                45 |
| Credential Access    |        37 |       1 |      18 |                56 |
| Defense Evasion      |       200 |       7 |      37 |               244 |
| Discovery            |         4 |       0 |       3 |                 7 |
| Execution            |        50 |      10 |      41 |               101 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        14 |       2 |       2 |                18 |
| Initial Access       |        45 |       1 |       2 |                48 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        49 |       2 |      16 |                67 |
| Privilege Escalation |        49 |       5 |       7 |                61 |
| Total by OS          |       485 |      31 |     148 |               664 |
