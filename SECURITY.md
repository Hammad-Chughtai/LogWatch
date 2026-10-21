# Security policy

Security fixes apply to the latest release on `main`.

For vulnerabilities in this project's code, use GitHub's **Report a vulnerability** option if private vulnerability reporting is enabled on the repository. If it is unavailable, open a minimal issue requesting a private reporting channel without including exploit details, secrets, or production logs. This project does not promise a response time.

Include the affected version, a synthetic reproduction, observed behavior, and likely impact through the private channel. Never publish real authentication logs or credentials in an issue.

The analyzer reads local files and writes reports to paths you specify. HTML values from logs are escaped; reports use a restrictive content security policy and contain no scripts or external assets. These measures do not anonymize data: accounts, hosts, addresses, and timestamps remain visible.

Treat input and output as potentially sensitive. Analyze copies of logs with appropriate access controls, keep generated reports outside public repositories, and inspect artifacts before sharing. Output files are replaced at the requested paths. Use `--strict` when rejected records must invalidate analysis.

This tool supplies evidence for human review and does not establish compromise or automatically respond to alerts.
