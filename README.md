# lab-reports
# 🛡️ SOC Home Lab — Incident Response & Hardening
 
Laboratório prático de cibersegurança focado em **Resposta a Incidentes (todas as fases)** e **Hardening** de servidores, dispositivos de rede e nuvem. Projetado para documentar experiência real alinhada a vagas de SOC Analyst / Security Engineer.
 
---
 
## 📋 Competências Desenvolvidas
 
| Área | O que você pratica |
|---|---|
| **Detecção** | Criação de regras SIEM, correlação de logs, alertas Wazuh/Elastic |
| **Contenção** | Isolamento de host, bloqueio de IP, quarentena de conta |
| **Erradicação** | Remoção de malware, limpeza de persistência, análise forense |
| **Recuperação** | Restore de snapshot, validação pós-incidente, documentação |
| **Hardening** | CIS Benchmarks em Linux, Windows Server, pfSense e AWS/GCP |
| **Playbooks / SLA** | Fluxos documentados com tempo de resposta por severidade |
 
---
 
## 🖥️ Arquitetura do Laboratório
 
```
HOST: Windows 10/11 (32GB RAM)
└── VMware Workstation Pro / VirtualBox
    ├── [VM1] pfSense            - Firewall/IDS (1GB RAM)
    ├── [VM2] Security Onion     - SIEM + NDR   (16GB RAM)
    ├── [VM3] Ubuntu Server      - Alvo Linux   (2GB RAM)
    ├── [VM4] Windows Server 2022- Alvo Windows (4GB RAM)
    ├── [VM5] Kali Linux         - Atacante      (4GB RAM)
    └── [VM6] Ubuntu Desktop     - Analista/DFIR (4GB RAM)
```
 
**Rede isolada:** `192.168.100.0/24` (sem acesso à internet real do lab)

- VM instaladas, pfSense configurado, ubuntu desktop acessando a rede 192.168.100.0/24, pfsense fazendo nat entre lan e wan,

- Realizando configuração do Security Onion 3.1.0
