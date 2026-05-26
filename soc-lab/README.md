# SOC Home Lab — Incident Response & Hardening

> Laboratório prático de cibersegurança construído para comprovar experiência real em **Resposta a Incidentes (todas as fases)** e **Hardening** de servidores, dispositivos de rede e serviços em nuvem.

---

## Sobre este repositório

Este repositório documenta a construção e operação de um laboratório de SOC doméstico, com evidências práticas de cada competência exercitada. Cada seção contém:

- Descrição técnica do que foi feito
- Comandos e configurações aplicadas
- **Espaços de evidência** para prints, vídeos e logs reais coletados durante os exercícios

---

## Índice

- [Arquitetura do Laboratório](#arquitetura-do-laboratório)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Evidências — Setup do Lab](#evidências--setup-do-lab)
- [Competência 1 — Resposta a Incidentes](#competência-1--resposta-a-incidentes)
  - [Fase: Detecção](#fase-detecção)
  - [Fase: Contenção](#fase-contenção)
  - [Fase: Erradicação](#fase-erradicação)
  - [Fase: Recuperação](#fase-recuperação)
  - [SLAs Praticados](#slas-praticados)
  - [Cenários Executados](#cenários-executados)
- [Competência 2 — Hardening](#competência-2--hardening)
  - [Linux — Ubuntu Server 22.04](#linux--ubuntu-server-2204)
  - [Windows — Windows Server 2022](#windows--windows-server-2022)
  - [Rede — pfSense Firewall](#rede--pfsense-firewall)
  - [Nuvem — AWS CIS Benchmark](#nuvem--aws-cis-benchmark)
- [Playbooks](#playbooks)
- [Scripts](#scripts)

---

## Arquitetura do Laboratório

```
HOST: Windows 10/11 (32 GB RAM) — VirtualBox
│
├── Rede do Lab: 192.168.100.0/24
│   ├── pfSense          192.168.100.1   Firewall · IDS Suricata
│   ├── Wazuh All-in-One 192.168.100.10  SIEM · HIDS · Dashboard
│   ├── Ubuntu Server    192.168.100.20  Alvo Linux
│   ├── Windows Server   192.168.100.30  Alvo Windows / AD
│   └── Ubuntu Desktop   192.168.100.40  Estação do Analista
│
└── Rede de Ataque: 192.168.200.0/24 (isolada)
    └── Kali Linux       192.168.200.50  Simulação de ataques
```

### Evidência — Diagrama de rede

> Adicione aqui um print do diagrama de rede ou da tela do VirtualBox mostrando todas as VMs

```
[ PRINT — Tela do VirtualBox com todas as VMs rodando ]
```

### Evidência — VMs em execução

```
[ PRINT — VirtualBox Manager mostrando o status "Running" de cada VM ]
```

---

## Tecnologias Utilizadas

| Categoria | Ferramenta | Função no Lab |
|---|---|---|
| Firewall / IDS | pfSense + Suricata | Controle de tráfego, detecção de intrusão na rede |
| SIEM / HIDS | Wazuh All-in-One | Correlação de eventos, alertas, compliance |
| Atacante | Kali Linux | Simulação de ataques (Metasploit, Hydra, Impacket) |
| Alvo Linux | Ubuntu Server 22.04 | Servidor vulnerável para prática de IR |
| Alvo Windows | Windows Server 2022 | Active Directory, RDP, SMB para prática de IR |
| Analista | Ubuntu Desktop | Wireshark, Velociraptor, coleta forense |
| Simulação MITRE | Atomic Red Team | Ataques mapeados ao ATT&CK framework |
| Scan de vuln. | OpenVAS / Greenbone | Identificação de vulnerabilidades pré/pós hardening |

---

## Evidências — Setup do Lab

### pfSense instalado e configurado

```
[ PRINT — Interface web do pfSense em https://192.168.100.1 ]
[ PRINT — Tela de regras de firewall (Firewall > Rules > LAN) ]
[ PRINT — Suricata ativo na interface LAN (Services > Suricata) ]
```

### Wazuh All-in-One instalado

```
[ PRINT — Dashboard do Wazuh em https://192.168.100.10 ]
[ PRINT — Tela de Agents mostrando Ubuntu Server e Windows Server conectados ]
[ PRINT — Terminal com saída do comando: sudo bash wazuh-install.sh -a ]
```

### Agentes Wazuh nos alvos

```
[ PRINT — Wazuh Dashboard > Agents > Ubuntu Server (status: Active) ]
[ PRINT — Wazuh Dashboard > Agents > Windows Server (status: Active) ]
```

### Conectividade da rede

```
[ PRINT — Terminal do Ubuntu Desktop com ping bem-sucedido para todos os hosts ]
```

---

## Competência 1 — Resposta a Incidentes

> Experiência prática em todas as fases do ciclo de resposta a incidentes (Detecção, Contenção, Erradicação e Recuperação), atuando conforme SLAs e Playbooks estruturados de SOC.

---

### Fase: Detecção

A detecção é realizada por três camadas complementares no lab:

**Camada 1 — Detecção de rede (Suricata no pfSense)**
O Suricata analisa o tráfego que passa pelo firewall usando regras ET Open e Snort Community, gerando alertas para comportamentos como port scanning, brute force, e tráfego C2.

**Camada 2 — Detecção em host (Wazuh HIDS)**
Agentes Wazuh instalados nos servidores alvo monitoram logs do sistema, criação de processos, modificação de arquivos críticos e execução de comandos privilegiados em tempo real.

**Camada 3 — Correlação no SIEM (Wazuh Manager)**
Eventos de todas as fontes são correlacionados no Wazuh Manager com regras customizadas baseadas no MITRE ATT&CK, gerando alertas com severidade e classificação de tática/técnica.

#### Evidências — Detecção

```
[ PRINT — Wazuh Dashboard > Security Events mostrando alertas ativos ]
[ PRINT — Alerta de brute force SSH disparado (regra 5710/5712) ]
[ PRINT — Alerta de execução de binário suspeito em /tmp ]
[ PRINT — Suricata alert no pfSense para tráfego C2 ]
[ VÍDEO — Demonstração: ataque executado no Kali → alerta aparecendo no Wazuh em tempo real ]
```

---

### Fase: Contenção

Após a detecção, o objetivo é impedir a propagação do incidente sem destruir evidências. As ações praticadas no lab:

**Contenção em host:** bloqueio de IP via `ufw`/`iptables`, encerramento de sessões ativas, bloqueio de conta comprometida.

**Contenção em rede:** criação de regra de bloqueio no pfSense para o IP atacante, isolamento da VM afetada alterando sua interface para uma rede isolada no VirtualBox.

**Coleta de evidências antes de agir:** uso do script `collect-evidence.sh` para capturar estado da memória, processos, conexões e logs antes de qualquer modificação no sistema.

#### Evidências — Contenção

```
[ PRINT — Terminal com comando ufw deny e confirmação do bloqueio ]
[ PRINT — pfSense > Firewall > Rules com regra de bloqueio do IP atacante criada ]
[ PRINT — Arquivo de evidências gerado pelo collect-evidence.sh com hash SHA-256 ]
[ PRINT — ss -tnp mostrando que a conexão maliciosa foi encerrada ]
[ VÍDEO — Demonstração do processo de isolamento de host ]
```

---

### Fase: Erradicação

Com o incidente contido, a erradicação remove completamente a presença do atacante do ambiente:

**Verificação de persistência:** inspeção de crontabs, serviços systemd criados recentemente, chaves SSH não autorizadas, usuários criados pelo atacante, e binários com SUID suspeito.

**Remoção:** exclusão segura de binários maliciosos (`shred`), remoção de usuários e chaves não autorizadas, limpeza de mecanismos de persistência encontrados.

**Validação:** verificação de integridade com `debsums`, comparação de hashes de arquivos críticos com baseline.

#### Evidências — Erradicação

```
[ PRINT — Terminal com saída da verificação de crontabs, authorized_keys e serviços suspeitos ]
[ PRINT — Remoção do binário malicioso com shred ]
[ PRINT — debsums mostrando integridade dos pacotes do sistema ]
[ PRINT — Wazuh Dashboard sem alertas ativos após erradicação ]
```

---

### Fase: Recuperação

A recuperação restaura o serviço de forma segura, com hardening aplicado para evitar reincidência:

**Restauração:** reconfiguração do serviço afetado, aplicação de hardening (SSH sem senha, fail2ban, regras de firewall revisadas).

**Validação:** testes funcionais confirmando que o serviço voltou ao normal e que o vetor de ataque original foi bloqueado.

**Monitoramento pós-incidente:** regras de detecção específicas adicionadas ao Wazuh para identificar recorrência do mesmo padrão de ataque.

#### Evidências — Recuperação

```
[ PRINT — /etc/ssh/sshd_config com PasswordAuthentication no e PermitRootLogin no ]
[ PRINT — fail2ban-client status sshd mostrando jail ativo ]
[ PRINT — Teste de tentativa de brute force bloqueado pelo fail2ban ]
[ PRINT — Wazuh > Rules mostrando nova regra criada pós-incidente ]
[ PRINT — Serviço funcionando normalmente após recuperação ]
```

---

### SLAs Praticados

Cada cenário executado registra timestamps de cada fase para comparação com os SLAs definidos:

| Severidade | SLA Detecção | SLA Contenção | SLA Recuperação |
|---|---|---|---|
| Crítico (P1) | < 15 min | < 1 hora | < 4 horas |
| Alto (P2) | < 30 min | < 4 horas | < 24 horas |
| Médio (P3) | < 2 horas | < 8 horas | < 72 horas |
| Baixo (P4) | < 24 horas | < 48 horas | < 1 semana |

#### Evidências — SLA

```
[ PRINT — Post-mortem do INC-001 com timeline completa e comparação de SLA ]
[ PRINT — Post-mortem do INC-002 com timeline completa e comparação de SLA ]
```

---

### Cenários Executados

#### INC-001 — SSH Brute Force (P2)

Playbook: [PB-001-bruteforce.md](soc-lab/docs/playbooks/PB-001-bruteforce.md)

Ataque simulado com Hydra do Kali Linux contra o Ubuntu Server. Detecção via regra Wazuh 5712, contenção com bloqueio de IP no pfSense e ufw, erradicação com verificação de persistência, recuperação com hardening SSH e fail2ban.

```
[ PRINT — Hydra executando no Kali (comando de ataque) ]
[ PRINT — Alerta disparado no Wazuh durante o ataque ]
[ PRINT — IP bloqueado no pfSense ]
[ PRINT — Post-mortem completo do INC-001 ]
[ VÍDEO — Walkthrough completo do cenário do início ao fim ]
```

#### INC-002 — Malware com C2 Callback (P1)

Playbook: [PB-002-malware-c2.md](soc-lab/docs/playbooks/PB-002-malware-c2.md)

Payload Meterpreter gerado no Kali, executado no Ubuntu Server, com sessão C2 ativa. Detecção via alerta de conexão de saída suspeita no Wazuh e Suricata. Contenção com isolamento do host, coleta forense de memória e erradicação do binário.

```
[ PRINT — Sessão Meterpreter ativa no Metasploit ]
[ PRINT — Alerta Suricata/Wazuh detectando o tráfego C2 ]
[ PRINT — Evidências coletadas pelo collect-evidence.sh ]
[ PRINT — Post-mortem completo do INC-002 ]
[ VÍDEO — Demonstração da detecção e resposta ]
```

---

## Competência 2 — Hardening

> Implementação de medidas de hardening e revisão de boas práticas de segurança em servidores Linux, Windows, dispositivos de rede e serviços em nuvem, baseado nos frameworks CIS Benchmark e DISA STIG.

---

### Linux — Ubuntu Server 22.04

Guia completo: [HRD-001-linux.md](soc-lab/docs/hardening/HRD-001-linux.md)
Script de automação: [linux-cis-hardening.sh](soc-lab/scripts/hardening/linux-cis-hardening.sh)

Framework aplicado: **CIS Ubuntu Linux 22.04 LTS Benchmark v1.0 — Level 1 e Level 2**

Controles implementados:

| Controle | Descrição | Status |
|---|---|---|
| Atualização do sistema | apt upgrade + unattended-upgrades | ✅ |
| Módulos desabilitados | cramfs, freevxfs, jffs2, hfs, squashfs, udf | ✅ |
| Kernel hardening | sysctl — ASLR, SYN cookies, log martians, RP filter | ✅ |
| SSH hardening | Sem root, sem senha, ciphers seguros, timeout 15min | ✅ |
| Firewall UFW | Default deny, rate limit SSH, regras mínimas | ✅ |
| Auditoria (auditd) | Regras CIS — identidade, sudoers, execução privilegiada | ✅ |
| Política de senhas | pwquality 14 chars, faillock 5 tentativas, 90 dias | ✅ |
| fail2ban | SSH jail ativo, bantime 1h | ✅ |
| AppArmor | Todos os perfis em enforce mode | ✅ |
| Serviços desabilitados | avahi, cups, rpcbind, telnet e outros | ✅ |

#### Evidências — Hardening Linux

```
[ PRINT — Saída do script linux-cis-hardening.sh com PASS/FAIL de cada controle ]
[ PRINT — cat /etc/ssh/sshd_config.d/99-cis.conf ]
[ PRINT — ufw status verbose ]
[ PRINT — auditctl -l mostrando regras ativas ]
[ PRINT — fail2ban-client status sshd ]
[ PRINT — apparmor_status ]
[ PRINT — Lynis audit score antes e depois do hardening ]
[ VÍDEO — Execução do script de hardening do início ao fim ]
```

---

### Windows — Windows Server 2022

Guia completo: [HRD-002-windows.md](soc-lab/docs/hardening/HRD-002-windows.md)

Framework aplicado: **CIS Microsoft Windows Server 2022 Benchmark v1.0 + DISA STIG**

Controles implementados:

| Controle | Descrição | Status |
|---|---|---|
| Conta Administrator | Renomeada para nome não padrão | ✅ |
| Conta Guest | Desabilitada | ✅ |
| Política de senhas | 14 chars, lockout 5 tentativas, 90 dias | ✅ |
| Auditoria avançada | Logon, Process Creation, Policy Change, Privilege Use | ✅ |
| Windows Defender | Real-time, Behavior Monitoring, Network Protection | ✅ |
| Firewall | Default deny inbound, logs habilitados | ✅ |
| SMBv1 | Desabilitado (previne EternalBlue/WannaCry) | ✅ |
| LSASS protegido | RunAsPPL = 1 (previne Mimikatz) | ✅ |
| UAC | Nível máximo com Secure Desktop | ✅ |
| PowerShell logging | Script Block Logging + Transcription | ✅ |
| RemoteRegistry | Desabilitado | ✅ |

#### Evidências — Hardening Windows

```
[ PRINT — PowerShell: Get-MpComputerStatus mostrando Defender ativo ]
[ PRINT — Get-SmbServerConfiguration | Select EnableSMB1Protocol (False) ]
[ PRINT — Get-NetFirewallProfile mostrando Enabled True nos 3 perfis ]
[ PRINT — auditpol /get /category:* com todas as políticas configuradas ]
[ PRINT — reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL (valor 1) ]
[ PRINT — C:\Windows\Logs\PowerShell com arquivos de transcript ]
[ VÍDEO — Aplicação do hardening via PowerShell ]
```

---

### Rede — pfSense Firewall

Guia completo: [HRD-003-pfsense.md](soc-lab/docs/hardening/HRD-003-pfsense.md)

Controles implementados:

| Controle | Descrição | Status |
|---|---|---|
| Senha padrão alterada | admin/pfsense substituída | ✅ |
| HTTPS na interface web | Acesso apenas por HTTPS | ✅ |
| Regras default deny | Política padrão bloqueio | ✅ |
| Isolamento da rede de ataque | Kali sem acesso à rede do lab | ✅ |
| IDS Suricata | Regras ET Open + Snort Community | ✅ |
| pfBlockerNG | Listas de IPs maliciosos e C2 bloqueados | ✅ |
| Logs para SIEM | Syslog enviado ao Wazuh na porta 514 | ✅ |
| Anti-spoofing | Habilitado em todas as interfaces | ✅ |

#### Evidências — Hardening pfSense

```
[ PRINT — pfSense > Firewall > Rules com todas as regras configuradas ]
[ PRINT — Services > Suricata mostrando interface ativa e alertas recentes ]
[ PRINT — pfBlockerNG > Reports com IPs bloqueados ]
[ PRINT — Status > System Logs > Settings com syslog remoto configurado ]
[ PRINT — Teste de ping do Kali para rede do lab sendo bloqueado ]
```

---

### Nuvem — AWS CIS Benchmark

Guia completo: [HRD-004-aws.md](soc-lab/docs/hardening/HRD-004-aws.md)

Framework aplicado: **CIS Amazon Web Services Foundations Benchmark v1.5**

Controles implementados:

| Controle CIS | Descrição | Status |
|---|---|---|
| 1.1 — Root MFA | MFA virtual ativo na conta root | ✅ |
| 1.4 — Root access keys | Nenhuma access key na root | ✅ |
| 1.8 — Password policy | Mínimo 14 chars, complexidade, 90 dias | ✅ |
| 1.10 — MFA usuários | MFA para todos os usuários IAM com console | ✅ |
| 2.1 — CloudTrail | Trail multi-região com validação de log | ✅ |
| 2.1.5 — S3 logging | Logs de acesso S3 habilitados | ✅ |
| 3.1 — S3 block public | Block Public Access ativo na conta | ✅ |
| 3.7 — EBS encryption | Criptografia padrão de EBS habilitada | ✅ |
| 4.1 — VPC Flow Logs | Flow Logs ativos na VPC | ✅ |
| 4.6 — IMDSv2 | Obrigatório em todas as instâncias EC2 | ✅ |
| 5.1 — GuardDuty | Ativo em todas as regiões utilizadas | ✅ |
| 5.3 — Security Hub | CIS benchmark ativo com findings | ✅ |

#### Evidências — Hardening AWS

```
[ PRINT — AWS Console > IAM > Security recommendations (tudo verde) ]
[ PRINT — CloudTrail > Trails com trail multi-região ativo ]
[ PRINT — S3 > Block Public Access settings (todos habilitados) ]
[ PRINT — GuardDuty > Summary mostrando o detector ativo ]
[ PRINT — Security Hub > Summary com score de conformidade CIS ]
[ PRINT — Saída do script AWS CLI com relatório de conformidade ]
[ VÍDEO — Walkthrough das configurações CIS no console AWS ]
```

---

## Playbooks

Os playbooks seguem a estrutura de um SOC real: classificação de severidade, fases documentadas com checkpoints, timestamps para medição de SLA, e template de post-mortem.

| ID | Cenário | Severidade | MITRE ATT&CK | Arquivo |
|---|---|---|---|---|
| PB-001 | SSH Brute Force | Alto (P2) | T1110.001 | [PB-001-bruteforce.md](soc-lab/docs/playbooks/PB-001-bruteforce.md) |
| PB-002 | Malware C2 Callback | Crítico (P1) | T1059, T1071 | [PB-002-malware-c2.md](soc-lab/docs/playbooks/PB-002-malware-c2.md) |

---

## Scripts

| Script | Função | Uso |
|---|---|---|
| [linux-cis-hardening.sh](soc-lab/scripts/hardening/linux-cis-hardening.sh) | Automação de hardening CIS L1/L2 no Ubuntu | `sudo bash linux-cis-hardening.sh` |
| [collect-evidence.sh](soc-lab/scripts/incident-response/collect-evidence.sh) | Coleta forense inicial em Linux | `sudo bash collect-evidence.sh INC-001` |

---

## Como Reproduzir Este Lab

Consulte o guia completo de instalação em [soc-lab/docs/01-setup-lab.md](soc-lab/docs/01-setup-lab.md).

Resumo das versões utilizadas:

- VirtualBox 7.x (host Windows 10/11)
- pfSense CE 2.7.x
- Wazuh All-in-One 4.9.x (Ubuntu Server 22.04)
- Ubuntu Server 22.04 LTS
- Windows Server 2022 Evaluation
- Kali Linux 2024.x
- Ubuntu Desktop 22.04 LTS

---

*Repositório mantido como portfólio de competências práticas em Cybersecurity — Incident Response & Hardening.*
