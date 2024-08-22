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
| production-rules-linux-v1 | 1.0.68 | e669b38da6c8d98eec7ce81a84bce10ac5a9f3e1a6dd7ec67d0f727686b03a41 |
| production-rules-macos-v1 | 1.0.68 | 007fecba6315431ce16897524fffbf99629926c279f176140f7db343cfd488c0 |
| production-rules-windows-v1 | 1.0.68 | f6328c76bcd9e3145fd0a0824bcfb0744c8a88270307aac10e2f4a19cc6c0bad |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.68', '1.0.67') by OS/MITRE Tactic.
| Tactic            |   Windows |   Linux |   macOS |   Total by Tactic |
|-------------------|-----------|---------|---------|-------------------|
| Collection        |         0 |       0 |       1 |                 1 |
| Credential Access |         0 |       0 |       1 |                 1 |
| Defense Evasion   |         0 |       1 |       2 |                 3 |
| Execution         |         0 |       1 |       0 |                 1 |
| Total by OS       |         0 |       2 |       4 |                 6 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        11 |       0 |       5 |                16 |
| Command and Control  |        31 |       4 |      26 |                61 |
| Credential Access    |        42 |       3 |      24 |                69 |
| Defense Evasion      |       239 |      15 |      43 |               297 |
| Discovery            |         6 |       0 |       4 |                10 |
| Execution            |        61 |      20 |      62 |               143 |
| Exfiltration         |         0 |       0 |       1 |                 1 |
| Impact               |        17 |       2 |       2 |                21 |
| Initial Access       |        49 |       2 |       2 |                53 |
| Lateral Movement     |         8 |       1 |       1 |                10 |
| Persistence          |        53 |      21 |      17 |                91 |
| Privilege Escalation |        58 |       7 |       8 |                73 |
| Total by OS          |       575 |      75 |     195 |               845 |



### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 

