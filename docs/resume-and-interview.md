# Resume & Interview Notes

## Resume project title
**AI-Enhanced SOC Monitoring Lab | Wazuh, Python, Docker, OpenAI**

## Resume bullets
- Built a virtualized SOC lab using Wazuh on Ubuntu Server to monitor a Windows 11 endpoint and detect real-time file integrity events.
- Deployed NetAlertX with Docker for network asset discovery and developed a Python integration that converts Wazuh FIM alerts into structured AI-assisted risk assessments through the OpenAI API.
- Configured Linux services, API authentication, firewall rules, REST endpoints, and automated analysis producing risk scores, severity, evidence, and recommended analyst actions.

## 30-second interview explanation
I built a home SOC lab with a Windows endpoint monitored by Wazuh running on an Ubuntu VM. I configured real-time file integrity monitoring, deployed NetAlertX in Docker for asset discovery, and wrote a Python service that reads Wazuh FIM alerts and sends selected event metadata to OpenAI. The service returns structured analyst-style output including a risk score, severity, evidence, and recommended actions, then exposes the latest result through an authenticated local API. The project gave me hands-on experience with SIEM monitoring, Linux, Docker, networking, APIs, systemd, firewall rules, and troubleshooting.

## Good discussion points
Be ready to explain why FIM matters, the difference between Wazuh detection and AI analysis, why the AI output should support rather than replace analyst judgment, how API keys were kept outside source code, why a dedicated Linux service account was used, and how you diagnosed UFW, Docker capability, API-authentication, disk-space, and API-credit issues.
