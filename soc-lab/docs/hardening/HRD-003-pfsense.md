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

Firewall > Rules > LAN
# Criar regra permitindo acesso à porta 443 apenas do analista:
Ação:    Pass
Origem:  192.168.100.40  (Ubuntu Desktop — analista)
Destino: 192.168.100.1
Porta:   443/TCP
Descrição: Acesso web pfSense apenas do analista
```

### 1.5 — Timeout de sessão

```
System > Advanced > Admin Access
Session Timeout: 30 (minutos)
```

#### Evidências — Autenticação

```
[ PRINT — System > User Manager com usuário soc-admin criado e admin desabilitado ]
[ PRINT — System > Advanced > Admin Access com HTTPS e timeout configurados ]
[ PRINT — Firewall > Rules > LAN com regra de acesso restrito à interface web ]
```

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

```
[ PRINT — System > General Setup com DNS e hostname configurados ]
[ PRINT — Services > NTP mostrando sincronização ativa ]
```

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

| Ordem | Ação | Origem | Destino | Porta | Descrição |
|---|---|---|---|---|---|
| 1 | Pass | LAN net | LAN address | 53, 67, 68 | DNS e DHCP interno |
| 2 | Block | 192.168.200.0/24 | 192.168.100.0/24 | any | Isolar rede Kali |
| 3 | Pass | 192.168.100.40 | 192.168.100.1 | 443 | Analista acessa pfSense |
| 4 | Pass | 192.168.100.40 | 192.168.100.20 | 22 | Analista SSH → Ubuntu |
| 5 | Pass | 192.168.100.40 | 192.168.100.30 | 3389 | Analista RDP → Windows |
| 6 | Pass | LAN net | 192.168.100.10 | 514/UDP | Syslog → Wazuh |
| 7 | Pass | LAN net | any | 80, 443, 53 | Updates internet |
| 8 | Block | any | any | any | Default deny |

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
- [ ] Rede de ataque (Kali) isolada da rede do lab
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
