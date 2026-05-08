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
| production-rules-linux-v1 | 1.0.116 | 747950d177366c895a1838367edc8d8d2f561f247e525b53951155ed51b17606 |
| production-rules-macos-v1 | 1.0.116 | 36144bb816c83837a119037dbf6c545f156d927084557d3349f94bf3f336c18f |
| production-rules-windows-v1 | 1.0.116 | fa308473d6ba76361a032b416de7aacff44766a2e2bba67a2a3e9d8cc3e91cc5 |

### Rules Summary per Tactic

Note: New Production Rules since last version ('1.0.116', '1.0.115') by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |         0 |       1 |       0 |                 1 |
| Command and Control  |         0 |       5 |       0 |                 5 |
| Defense Evasion      |         0 |       7 |       0 |                 7 |
| Discovery            |         0 |       1 |       1 |                 2 |
| Execution            |         0 |       4 |       1 |                 5 |
| Initial Access       |         0 |       2 |       0 |                 2 |
| Persistence          |         0 |       4 |       0 |                 4 |
| Privilege Escalation |         0 |       1 |       0 |                 1 |
| Total by OS          |         0 |      25 |       2 |                27 |

Note: Latest Total Production Rules by OS/MITRE Tactic.

| Tactic               |   Windows |   Linux |   macOS |   Total by Tactic |
|----------------------|-----------|---------|---------|-------------------|
| Collection           |        12 |       1 |       8 |                21 |
| Command and Control  |        40 |      16 |      41 |                97 |
| Credential Access    |        53 |       7 |      35 |                95 |
| Defense Evasion      |       322 |      55 |      61 |               438 |
| Discovery            |        20 |       2 |       2 |                24 |
| Execution            |        97 |      63 |     106 |               266 |
| Exfiltration         |         0 |       0 |       2 |                 2 |
| Impact               |        19 |       6 |       2 |                27 |
| Initial Access       |        62 |       3 |       2 |                67 |
| Lateral Movement     |        10 |       2 |       1 |                13 |
| Persistence          |        61 |      30 |      21 |               112 |
| Privilege Escalation |        75 |      16 |       9 |               100 |
| Total by OS          |       771 |     201 |     290 |              1262 |

### MITRE ATT&CK Coverage

#### XDR MITRE scorecard (endpoint + endpoint-scoped SIEM)

- Catalog: 61 parent techniques (Win/Linux/macOS under 8 scorecard tactics)
- Covered (union): 49/61 (80.33%) — production endpoint rules plus production SIEM rules with metadata.integration including "endpoint" and/or index matching logs-endpoint.events* / logs-endpoint.alerts*
- Techniques — endpoint-only: 1, SIEM-only: 5, both: 43
- Rules — production endpoint: 1231, SIEM (in-scope + MITRE): 991

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
