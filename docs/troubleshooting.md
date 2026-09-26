# Troubleshooting & Lessons Learned

| Problem | Resolution |
|---|---|
| Wazuh/OS compatibility | Rebuilt the VM on Ubuntu Server 24.04 LTS. |
| VM disk became full | Expanded available Linux/LVM storage. |
| Windows agent communication failed | Corrected UFW rules for Wazuh ports 1514/1515. |
| NetAlertX container restarted | Added required network capabilities and host networking. |
| NetAlertX API returned 403 | Corrected/persisted API-token configuration. |
| OpenAI API returned 429 | Corrected API billing/credit availability. |
| VMware console paste was inconvenient | Used Windows PowerShell over SSH for Ubuntu administration. |

These issues provided hands-on experience troubleshooting networking, Linux permissions, storage, Docker, API authentication, and service configuration.
