# 01 — Setup do Laboratório

## Arquitetura

```
HOST Windows 10/11 (32 GB RAM, SSD)
│
└── VirtualBox 7.x
    │
    ├── [Rede do Lab: 192.168.100.0/24]
    │   ├── pfSense          192.168.100.1    Firewall + IDS
    │   ├── Wazuh AIO        192.168.100.10   SIEM + HIDS
    │   ├── Ubuntu Server    192.168.100.20   Alvo Linux
    │   ├── Windows Server   192.168.100.30   Alvo Windows
    │   └── Ubuntu Desktop   192.168.100.40   Analista
    │
    └── [Rede de Ataque: 192.168.200.0/24]
        └── Kali Linux       192.168.200.50   Atacante
```

## Requisitos de Hardware por VM

| VM | SO | RAM | Disco | vCPUs |
|---|---|---|---|---|
| pfSense | FreeBSD | 1 GB | 20 GB | 2 |
| Wazuh AIO | Ubuntu 22.04 | 4 GB | 50 GB | 2 |
| Ubuntu Server | Ubuntu 22.04 | 2 GB | 40 GB | 2 |
| Windows Server | WS 2022 | 4 GB | 60 GB | 2 |
| Kali Linux | Debian | 4 GB | 40 GB | 2 |
| Ubuntu Desktop | Ubuntu 22.04 | 4 GB | 40 GB | 2 |
| **TOTAL** | | **19 GB** | **250 GB** | **12** |

---

## Passo 1 — Redes Virtuais no VirtualBox

No VirtualBox, crie duas redes internas:

```
Menu: File > Tools > Network Manager > Host-only Networks

LabNet:    192.168.100.0/24  (desabilitar DHCP — pfSense vai fazer)
AttackNet: 192.168.200.0/24  (desabilitar DHCP)
```

### Evidência

<img width="574" height="228" alt="Image" src="https://github.com/user-attachments/assets/ff179d4e-fc2a-478a-9809-3f866be579f4" />

---

## Passo 2 — pfSense

Download: https://www.pfsense.org/download/ (CE, AMD64, DVD Image)

Configuração da VM:
- Adaptador 1: NAT (WAN — acesso internet)
- Adaptador 2: LabNet (LAN — 192.168.100.1)

Após instalação, acesse `https://192.168.100.1` e configure via Setup Wizard.

### Evidência

<img width="1274" height="887" alt="Image" src="https://github.com/user-attachments/assets/2dc23e40-0a96-411c-b80c-28fd393f6fe1" />
---

## Passo 3 — Wazuh All-in-One 
sudo 
VM: Ubuntu Server 22.04 | 4 GB RAM | 50 GB disco | 1 adaptador: LabNet

```bash
# Configurar IP fixo antes de instalar
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [192.168.100.10/24]
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
  version: 2
```

```bash
sudo netplan apply

# Instalar Wazuh AIO
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.9/config.yml
```

Editar `config.yml`:

```yaml
nodes:
  indexer:
    - name: node-1
      ip: 192.168.100.10
  server:
    - name: wazuh-1
      ip: 192.168.100.10
  dashboard:
    - name: dashboard
      ip: 192.168.100.10
```

```bash
sudo bash wazuh-install.sh -a
# Ao final: anotar usuário e senha gerados
```

Acesse: `https://192.168.100.10`

### Evidência

```
[ PRINT — Terminal com saída final do wazuh-install.sh mostrando sucesso ]
<img width="1277" height="918" alt="Image" src="https://github.com/user-attachments/assets/a1b26b9e-da24-47a3-bc85-16aa57565a5c" />
[ PRINT — Dashboard do Wazuh acessado pelo Ubuntu Desktop ]
<img width="1282" height="884" alt="Image" src="https://github.com/user-attachments/assets/f0878a2a-b59b-4f83-9d15-1b4bb4aee40b" />
[ PRINT — Wazuh > Agents com todos os agentes conectados ]
```

---

## Passo 4 — Ubuntu Server (Alvo Linux)

VM: Ubuntu Server 22.04 | 2 GB RAM | 40 GB | LabNet

```bash
# IP fixo
sudo nano /etc/netplan/00-installer-config.yaml
# addresses: [192.168.100.20/24] | gateway: 192.168.100.1

sudo netplan apply

# Instalar agente Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --dearmor | sudo tee /usr/share/keyrings/wazuh.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update && sudo apt install wazuh-agent -y

sudo sed -i 's/MANAGER_IP/192.168.100.10/' /var/ossec/etc/ossec.conf
sudo systemctl enable --now wazuh-agent
```

### Evidência

```
[ PRINT — Wazuh Dashboard > Agents > Ubuntu Server (status: Active) ]
```

---

## Passo 5 — Windows Server 2022 (Alvo Windows)

Download: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022

```powershell
# IP fixo
New-NetIPAddress -InterfaceAlias "Ethernet" `
  -IPAddress 192.168.100.30 -PrefixLength 24 `
  -DefaultGateway 192.168.100.1

# Instalar agente Wazuh (baixar MSI em packages.wazuh.com)
msiexec.exe /i wazuh-agent.msi /q `
  WAZUH_MANAGER="192.168.100.10" `
  WAZUH_AGENT_NAME="windows-server"

# Habilitar logs avançados
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

### Evidência

```
[ PRINT — Wazuh Dashboard > Agents > Windows Server (status: Active) ]
```

---

## Passo 6 — Kali Linux (Atacante)

VM: Kali Linux | 4 GB RAM | 40 GB | AttackNet

```bash
# IP fixo
sudo nano /etc/network/interfaces
# address 192.168.200.50
# netmask 255.255.255.0
# gateway 192.168.200.1

# Rota para atacar a rede do lab (ativada só durante exercícios)
sudo ip route add 192.168.100.0/24 via 192.168.200.1

# Atomic Red Team
cd /opt
sudo git clone https://github.com/redcanaryco/atomic-red-team.git
```

### Evidência

```
[ PRINT — Kali com ferramentas principais: msfconsole, hydra, nmap ]
```

---

## Passo 7 — Ubuntu Desktop (Analista)

VM: Ubuntu Desktop 22.04 | 4 GB RAM | 40 GB | LabNet

```bash
# IP fixo: 192.168.100.40/24

# Ferramentas do analista
sudo apt install -y wireshark tshark curl wget git vim

# Velociraptor (DFIR)
wget https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-linux-amd64
chmod +x velociraptor-linux-amd64
sudo mv velociraptor-linux-amd64 /usr/local/bin/velociraptor

# Acesso ao Wazuh via Firefox
# https://192.168.100.10
```

### Evidência

```
[ PRINT — Ubuntu Desktop com Firefox aberto no Wazuh Dashboard ]
[ PRINT — Terminal com ping bem-sucedido para todos os hosts do lab ]
```

---

## Snapshot — Baseline

Após o setup completo, criar snapshot de cada VM:

```
Nome: "baseline-clean"
Descrição: "Estado inicial — antes de qualquer cenário de ataque"
```

Isso permite resetar o lab após cada exercício.

### Evidência

```
[ PRINT — VirtualBox mostrando snapshot "baseline-clean" em cada VM ]
```
