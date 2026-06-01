# HRD-003 — Hardening pfSense Firewall

**Framework:** CIS Controls v8 + Boas Práticas Netgate/pfSense  
**Ambiente:** VM pfSense CE 2.7.x no lab  
**Acesso:** `https://192.168.100.1` pelo Ubuntu Desktop  

---

## Antes de Começar

```
# Snapshot ANTES do hardening
VirtualBox > VM pfSense > Snapshots > Take Snapshot "pre-hardening"
```

---

## 1. ACESSO E AUTENTICAÇÃO

### 1.1 — Alterar senha padrão

A senha `admin/pfsense` é conhecida publicamente e deve ser trocada imediatamente após a instalação.

```
System > User Manager > Users > admin > Edit
Password: (definir senha forte — mínimo 14 chars, letras, números e símbolos)
```

### 1.2 — Criar usuário administrativo próprio e desabilitar admin padrão

```
System > User Manager > Users > Add
Username:   soc-admin
Password:   (senha forte)
Group:      admins

# Após criar e validar o acesso com soc-admin:
# Desabilitar o usuário "admin" padrão
admin > Edit > Disabled: ✅
```

### 1.3 — Forçar HTTPS e desabilitar HTTP

```
System > Advanced > Admin Access
Protocol:          HTTPS
SSL/TLS Certificate: (gerar certificado autoassinado em System > Cert Manager)
TCP Port:          443
```

### 1.4 — Restringir acesso à interface web por IP
 
```
System > Advanced > Admin Access
TCP Port:          443
Login Protection:  ✅ habilitado
Anti-Lockout Rule: manter ativo durante configuração, desabilitar após
```
 
No pfSense, as regras são processadas **de cima para baixo** — a primeira que casar é aplicada e o processamento para. Por isso a regra de permissão do analista precisa vir **antes** da regra de bloqueio geral. São duas regras obrigatórias:
 
```
Firewall > Rules > LAN
 
# REGRA 1 — Permitir apenas o analista (deve ficar ACIMA da regra de bloqueio)
Ação:      Pass
Origem:    192.168.100.40
Destino:   192.168.100.1
Porta:     443/TCP
Descrição: Analista acessa interface web do pfSense
 
# REGRA 2 — Bloquear todos os outros hosts da LAN (deve ficar ABAIXO da regra acima)
Ação:      Block
Origem:    192.168.100.0/24
Destino:   192.168.100.1
Porta:     443/TCP
Descrição: Bloquear acesso à interface web para qualquer outro host
```
 
**Como funciona na prática:**
- Host `192.168.100.40` (analista) → casa na Regra 1 → **acesso permitido**
- Host `192.168.100.20` (Ubuntu Server) → não casa na Regra 1, casa na Regra 2 → **bloqueado**
- Host `192.168.100.50` (Kali) → não casa na Regra 1, casa na Regra 2 → **bloqueado**
Sem a Regra 2 explícita, qualquer host da LAN chegaria na regra geral `LAN → any` mais abaixo e teria acesso à interface web do pfSense.
 
### 1.5 — Timeout de sessão

```
System > Advanced > Admin Access
Session Timeout: 30 (minutos)
```

#### Evidências — Autenticação


<img width="1279" height="792" alt="Image" src="https://github.com/user-attachments/assets/6c137bba-2bb8-4046-9333-159213149364" />
<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/ddbd1d3c-96b3-4ab1-8d6e-6ce29fb6f501" />



---

## 2. INTERFACE WEB — CONFIGURAÇÕES GERAIS

### 2.1 — Desabilitar serviços não utilizados na console serial

```
System > Advanced > Admin Access
Console Options:
  Password protect the console menu: ✅
```

### 2.2 — Configurar DNS seguro

```
System > General Setup
DNS Servers:
  1.1.1.1  (Cloudflare)
  8.8.8.8  (Google)

DNS Resolution Behavior: Use local DNS, fall back to remote
```

### 2.3 — Configurar NTP

```
System > General Setup
Timezone: America/Sao_Paulo

Services > NTP
Time Servers: pool.ntp.br
```

Sincronização de tempo correta é crítica para correlação de logs no SIEM — eventos com timestamps incorretos quebram a linha do tempo de um incidente.

#### Evidências — Configurações Gerais


<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/5dd4254c-1e55-4d5c-bfba-0d32ac952d6e" />
<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/7e71da34-41bf-41b7-8938-85293e9d5dec" />

---

## 3. REGRAS DE FIREWALL

### 3.1 — Política padrão (default deny)

```
Firewall > Rules > WAN
# Verificar que não há regras permissivas abertas para a internet
# A política padrão WAN já bloqueia entrada — confirmar que está assim

Firewall > Rules > LAN
# Regras em ordem (pfSense processa de cima para baixo):
```

### Tabela de Regras de Firewall - Interface LAN

| Ordem | Ação | Origem | Destino | Porta | Descrição |
|---|---|---|---|---|---|
| 1 | Pass | LAN subnets | LAN address | 67-68 | DHCP Interno |
| 2 | Pass | LAN subnets | LAN address | 53 | DNS Interno TCP |
| 3 | Pass | LAN subnets | LAN address | 53 | DNS Interno UDP |
| 4 | Pass | LAN subnets | any | any | PING ICMP |
| 5 | Pass | LAN subnets | any | 123 | NTP Interno |
| 6 | Block | 192.168.100.50 | any | any | Bloquear Kali |
| 7 | Pass | 192.168.100.40 | 192.168.100.1 | 443 | Analista acessa pfSense |
| 8 | Pass | 192.168.100.40 | 192.168.100.20 | 22 | Analista SSH $\rightarrow$ Ubuntu |
| 9 | Pass | 192.168.100.40 | 192.168.100.30 | 3389 | TCP - Analista RDP $\rightarrow$ Windows |
| 10 | Pass | 192.168.100.40 | 192.168.100.30 | 3389 | UDP - Analista RDP $\rightarrow$ Windows |
| 11 | Pass | LAN subnets | 192.168.100.10 | 514 | Syslog $\rightarrow$ Wazuh |
| 12 | Pass | any | any | 443 | HTTPS Updates internet |
| 13 | Pass | any | any | 80 | HTTP Updates internet |

<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/5391f714-6751-4ce2-ac6a-7101e1c23e1b" />

### 3.2 — Anti-spoofing

```
Interfaces > WAN > Edit
Block private networks: ✅
Block bogon networks:   ✅
```

### 3.3 — Desabilitar respostas a ping na WAN

```
Firewall > Rules > WAN
# Verificar que não existe regra permitindo ICMP de any para WAN address
# Por padrão já bloqueado — confirmar e documentar
```

#### Evidências — Firewall

```
[ PRINT — Firewall > Rules > LAN com todas as regras na ordem correta ]
[ PRINT — Firewall > Rules > WAN mostrando Block private/bogon habilitados ]
[ PRINT — Teste: ping do Kali para 192.168.100.20 sendo bloqueado (terminal Kali) ]
```

---

## 4. SURICATA (IDS/IPS)

### 4.1 — Instalação

```
System > Package Manager > Available Packages
Buscar: suricata
Instalar: Suricata
```

### 4.2 — Configuração inicial

```
Services > Suricata > Global Settings
  Update Interval: 6 hours
  Remover regras ao desinstalar: ✅

Services > Suricata > Update Rules
  Clicar "Update" para baixar regras iniciais
```

### 4.3 — Configurar interface LAN

```
Services > Suricata > Interfaces > Add

Interface:          LAN
Description:        LAN-IDS
Send Alerts to Log: ✅
Block Offenders:    ❌ (IDS mode — monitorar sem bloquear no início)
Which IP to Block:  SRC

# Aba Rules:
Snort Community:    ✅
ET Open:            ✅ (Emerging Threats — cobertura ampla)

# Aba Logs Settings:
Enable EVE JSON:    ✅  ← necessário para integração com Wazuh
EVE Log:            alerts, flows, http, dns, tls
```

### 4.4 — Iniciar o Suricata

```
Services > Suricata > Interfaces
Clicar no botão ▶ (Start) na interface LAN
Status deve mostrar: ✅ Running
```

### 4.5 — Integrar logs Suricata ao Wazuh

```
Status > System Logs > Settings

Enable Remote Logging:     ✅
Remote Log Server 1:       192.168.100.10
Remote Syslog Port:        514
Remote Syslog Protocol:    UDP
Log All:                   ✅
```

#### Evidências — Suricata

```
[ PRINT — Services > Suricata > Interfaces com status Running na LAN ]
[ PRINT — Services > Suricata > Alerts mostrando alertas após teste de ataque ]
[ PRINT — Status > System Logs > Settings com syslog remoto para Wazuh configurado ]
[ PRINT — Wazuh Dashboard recebendo eventos do pfSense ]
```

---

## 5. pfBLOCKERNG (THREAT INTELLIGENCE)

### 5.1 — Instalação

```
System > Package Manager > Available Packages
Buscar: pfblockerng-devel
Instalar: pfBlockerNG-devel
```

### 5.2 — Configuração inicial

```
Firewall > pfBlockerNG > General
  Enable pfBlockerNG: ✅
  Keep Settings:      ✅

Firewall > pfBlockerNG > IP > IPv4
Adicionar feeds:
```

| Feed | URL | Categoria | Ação |
|---|---|---|---|
| Spamhaus DROP | https://www.spamhaus.org/drop/drop.txt | IPs maliciosos | Deny Both |
| Spamhaus EDROP | https://www.spamhaus.org/drop/edrop.txt | IPs maliciosos | Deny Both |
| Feodo Tracker | https://feodotracker.abuse.ch/downloads/ipblocklist.txt | C2 Banking | Deny Both |
| Emerging Threats C2 | https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt | C2 geral | Deny Both |

```
Firewall > pfBlockerNG > Update
Clicar "Run" para aplicar os feeds
```

#### Evidências — pfBlockerNG

```
[ PRINT — pfBlockerNG > General com status Enable ativo ]
[ PRINT — pfBlockerNG > IP > IPv4 com os feeds configurados ]
[ PRINT — pfBlockerNG > Reports > IP mostrando IPs bloqueados ]
```

---

## 6. LOGS E MONITORAMENTO

### 6.1 — Aumentar retenção de logs locais

```
Status > System Logs > Settings
Log Firewall Default Blocks: ✅
Log Packets Matched by Default Pass Rules: ✅
GUI Log Entries: 500
Log File Size: 10485760  (10 MB)
```

### 6.2 — Verificar logs em tempo real

```
Status > System Logs > Firewall
# Monitorar pacotes bloqueados em tempo real

Status > System Logs > System
# Eventos do sistema, autenticações, erros
```

#### Evidências — Logs

```
[ PRINT — Status > System Logs > Firewall com pacotes bloqueados visíveis ]
```

---

## 7. ATUALIZAÇÕES

```
System > Update > System Update
Branch: Latest stable version
Verificar e aplicar atualizações disponíveis

System > Package Manager > Installed Packages
Atualizar todos os pacotes instalados
```

#### Evidências — Atualizações

```
[ PRINT — System > Update mostrando sistema atualizado ]
```

---

## Checklist Final

- [ ] Senha padrão `admin/pfsense` alterada
- [ ] Usuário administrativo próprio criado
- [ ] Acesso à interface web restrito ao IP do analista
- [ ] HTTPS obrigatório com timeout de 30 minutos
- [ ] Console serial protegida por senha
- [ ] NTP sincronizado (America/Sao_Paulo)
- [ ] Regras de firewall em ordem com default deny
- [ ] Anti-spoofing habilitado na WAN
- [ ] Kali Linux (192.168.100.50) bloqueado por regra de firewall quando não há cenário ativo
- [ ] Suricata ativo em modo IDS na interface LAN
- [ ] Regras ET Open e Snort Community baixadas
- [ ] Logs EVE JSON habilitados no Suricata
- [ ] Syslog enviando eventos ao Wazuh (192.168.100.10:514)
- [ ] pfBlockerNG com feeds de threat intelligence ativos
- [ ] Sistema e pacotes atualizados
- [ ] Snapshot "pós-hardening" criado

---

## Referências

- [pfSense Documentation — Security Hardening](https://docs.netgate.com/pfsense/en/latest/security/index.html)
- [CIS Controls v8 — Control 4 (Secure Configuration)](https://www.cisecurity.org/controls/v8)
- [Suricata pfSense Integration](https://docs.netgate.com/pfsense/en/latest/packages/suricata/)
- [pfBlockerNG Documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
