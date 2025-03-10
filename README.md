# IAMPwn3r - Gotta Pwn ’Em All

IAMPwner is a Python-based tool designed to detect risky or misconfigured IAM (Identity and Access Management) permissions and roles within cloud tokens. It is especially useful during security engagements when access tokens for cloud services like AWS, Azure, or GCP are discovered. By analyzing these tokens, IAMPwner identifies potentially dangerous permissions that could lead to privilege escalation or lateral movement.

The tool works by querying the respective cloud APIs (AWS, Azure, GCP) to test and evaluate IAM permissions associated with a given access token. It helps security professionals identify attack paths by revealing misconfigurations or overly permissive roles that attackers could exploit. Whether it's escalating privileges in AWS, accessing sensitive resources in Azure, or discovering weak permissions in GCP, IAMPwner provides insights into potential vulnerabilities, enabling proactive threat mitigation and strengthening security posture during cloud security assessments.

** Currently support AWS - GCP in progress..
