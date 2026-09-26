# Implementation

## Environment
- Windows 11 endpoint: `192.168.1.124`
- Ubuntu Server 24.04 LTS: `192.168.1.245`
- Lab network: `192.168.1.0/24`
- Ubuntu interface: `ens33`

## Wazuh
Wazuh 4.14.7 was deployed on Ubuntu. A Windows agent named `windows-laptop` was enrolled and validated as active.

Real-time FIM monitored `C:\Wazuh-FIM-Test`. Testing generated Rule 554 for file creation and Rule 550 for a subsequent integrity checksum change.

## NetAlertX
NetAlertX ran in Docker with host networking and persistent storage. Device discovery and the authenticated `/devices` API were successfully tested.

## AI forwarder
A dedicated `wazuh-ai` system account runs the Python helper through systemd. The helper reads Wazuh JSON alerts, processes FIM events, sends selected metadata to OpenAI, stores structured analysis, and exposes `/health`, `/api/latest`, and `/api/analyses`.
