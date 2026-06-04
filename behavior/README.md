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
| production-rules-linux-v1 | 1.0.118 | d04323ba4325cc85c6b1a6c3a5fb1f76ea0aab8ff8eebeed3961e7c2c84013ee |
| production-rules-macos-v1 | 1.0.118 | cbf7d7fe6d9ec64eb44669f40f2a838686ecccf1d210cfddef8cd3316e3beffa |
| production-rules-windows-v1 | 1.0.118 | 13dc031d9fc08f37d794488672621b15fbc7d27a82e6654cec8b44e56b8da3b4 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.118', '1.0.117') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Command and Control  |         0 |       1 |       0 |                 1 |
| Defense Evasion      |         1 |       0 |       0 |                 1 |
| Privilege Escalation |         0 |       1 |       0 |                 1 |
| Total by OS          |         1 |       2 |       0 |                 3 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        13 |       3 |      10 |                26 |
| Command and Control  |        40 |      19 |      41 |               100 |
| Credential Access    |        52 |       7 |      34 |                93 |
| Defense Evasion      |       323 |      58 |      61 |               442 |
| Discovery            |        20 |       3 |       2 |                25 |
| Execution            |        97 |      64 |     105 |               266 |
| Exfiltration         |         0 |       1 |       2 |                 3 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       3 |       2 |                67 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        61 |      31 |      21 |               113 |
| Privilege Escalation |        75 |      19 |       9 |               103 |
| Total by OS          |       772 |     216 |     290 |              1278 |

### MITRE ATT&CK Coverage

#### XDR MITRE scorecard (endpoint + endpoint-scoped SIEM)

- Catalog: 61 parent techniques (Win/Linux/macOS under 8 scorecard tactics)
- Covered (union): 49/61 (80.33%) — production endpoint rules plus production SIEM rules with metadata.integration including "endpoint" and/or index matching logs-endpoint.events*/ logs-endpoint.alerts*
- Techniques — endpoint-only: 1, SIEM-only: 4, both: 44
- Rules — production endpoint: 1251, SIEM (in-scope + MITRE): 1005

#### Uncovered scorecard techniques (12 distinct parents; listed under each tactic where ATT&CK places them)

- Execution
  - T1674  Input Injection
- Persistence
  - T1668  Exclusive Control
  - T1653  Power Settings
- Defense Evasion
  - T1622  Debugger Evasion
  - T1678  Delay Execution
  - T1480  Execution Guardrails
  - T1207  Rogue Domain Controller
  - T1679  Selective Exclusion
  - T1221  Template Injection
- Credential Access
  - T1111  Multi-Factor Authentication Interception
- Impact
  - T1561  Disk Wipe
  - T1529  System Shutdown/Reboot
