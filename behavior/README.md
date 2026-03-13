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
| production-rules-linux-v1 | 1.0.111 | 824e008b86250fd427020c14f12ee0daf9ee39089614465da4395863e8ac1f2a |
| production-rules-macos-v1 | 1.0.111 | 61f87628acb24b9faadd8ac11aa9ce0673934b6247c88e5f9628caf8b9edae2f |
| production-rules-windows-v1 | 1.0.111 | c4e107470dc095518197010799fb9eead4509eb368838de326fdef0b60a67e92 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.111', '1.0.110') by OS/MITRE Tactic.

| Tactic              |   Windows |   Linux |   macOS |   Total by Tactic |
|---------------------|-----------|---------|---------|-------------------|
| Command and Control |         0 |       2 |       1 |                 3 |
| Defense Evasion     |         0 |       1 |       0 |                 1 |
| Execution           |         0 |       4 |       0 |                 4 |
| Initial Access      |         0 |       1 |       0 |                 1 |
| Total by OS         |         0 |       8 |       1 |                 9 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       0 |       8 |                20 |
| Command and Control  |        39 |      11 |      42 |                92 |
| Credential Access    |        52 |       7 |      34 |                93 |
| Defense Evasion      |       319 |      44 |      59 |               422 |
| Discovery            |        20 |       1 |       1 |                22 |
| Execution            |        93 |      57 |     103 |               253 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       1 |       2 |                65 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        60 |      25 |      20 |               105 |
| Privilege Escalation |        71 |      14 |       9 |                94 |
| Total by OS          |       757 |     168 |     283 |              1208 |
