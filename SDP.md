### Elastic Defend Safe Deployment Practices (SDP)

The Safe Deployment Practices (SDP) employed by Elastic Defend ensure its stable operation for our customers. We understand that security software updates can be disruptive if not handled carefully. Therefore, we have designed our SDP with the following core principles in mind:

- **Automated and Rigorous Testing**: We utilize extensive automated testing throughout the deployment pipeline. This includes unit tests and end-to-end system tests to identify and resolve potential issues before they reach customers.
- **Staged Artifact Deployments**: We employ staged deployments to minimize the impact of potential issues. Updates are rolled out to a small subset of users or environments initially and then gradually expanded to the entire user base.
- **Continuous Monitoring and Rollback**: We continuously monitor the health and performance of Elastic Defend deployments. Throughout the deployment window, we track key metrics to measure the health of the update. Our system automatically recognizes stability issues or other abnormalities. In the event of an issue, the deployment is blocked and all hosts return to the known stable artifact. 
- [Customer Empowerment and Control](#customer-control): We believe in giving our customers control over their security environment. We provide features that allow customers to manage and control updates according to their needs and risk tolerance.

### Rigorous Testing
Elastic Defend employs a multi-layered testing approach to ensure the quality and stability of our releases:

- **Unit Tests**: Each artifact repository contains unit tests to ensure that artifacts are correctly formatted and logically sound.
- **Full End-to-End Testing**: We perform full end-to-end testing for every artifact update on real systems. This process simulates real-world scenarios by detonating known malware and goodware across all supported platforms (Windows, Linux, macOS). It identifies any instabilities before release.
- **Diagnostic Mode Testing:** To further reduce the risk of false positives, we utilize diagnostic mode testing. Before any protections are deployed in an active mode, they are run in passive ("diagnostic") mode. This allows us to collect telemetry and fine-tune new protections without impacting customer systems.

### Staged Artifact Deployments
All Elastic Defend artifact updates are shipped through our staged deployment system to mitigate disruptions caused by unstable updates.

- **Gradual Rollout**: Artifact updates are initially applied to a set of Elastic internal endpoints. Next, the updates are applied to a slowly increasing number of customer machines over a gradual deployment period.
- **Health Telemetry and Monitoring**: Throughout the rollout, we continuously collect health telemetry from the participating endpoints. This telemetry includes information on system stability, crashes, false positives, and policy failures.
- **Automated Rollback**: If at any point key health metrics drop below established thresholds, the deployment is automatically halted, and all endpoints revert to the prior stable artifact.

### Customer Control
We believe in providing our customers with the flexibility to manage their Elastic Defend deployments.

- **Binary Upgrades**: Customers have full control over all binary upgrades of Elastic Defend. We do not automatically upgrade Elastic Defend binaries on our users’ behalf.
- **Artifact Pinning**: Customers can leverage [artifact pinning](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-updates-for-protection-artifacts) to lock artifact updates to a date of their choosing. This provides customers with lower risk tolerance the ability to test artifact updates internally before rolling them out to their entire fleet.
- **Release Channels**: Users can select a release channel in [advanced policy options](https://www.elastic.co/docs/reference/security/defend-advanced-settings) to control their participation in the staged artifact deployment:
  1. **Rapid**: Immediately receive candidate artifacts at the start of staged rollout.
  2. **Default**: Can receive stable or candidate artifacts probabilistically during the staged rollout window.
  3. **Stable**: No participation in staged deployment.
