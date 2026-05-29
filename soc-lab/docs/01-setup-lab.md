# 01 — Setup do Laboratório

## Arquitetura

```
HOST Windows 10/11 (32 GB RAM, SSD)
│
└── VirtualBox 7.x
    │
    ├── [Rede do Lab: 192.168.100.0/24]
        ├── pfSense          192.168.100.1    Firewall + IDS
        ├── Wazuh AIO        192.168.100.10   SIEM + HIDS
        ├── Ubuntu Server    192.168.100.20   Alvo Linux
        ├── Windows Server   192.168.100.30   Alvo Windows
        ├── Ubuntu Desktop   192.168.100.40   Analista
        └── Kali Linux       192.168.100.50   Atacante
    
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

No VirtualBox, crie rede interna:

```
Menu: File > Tools > Network Manager > Host-only Networks

LabNet:    192.168.100.0/24  (desabilitar DHCP — pfSense vai fazer)

```

### Evidência

<img width="1231" height="814" alt="Image" src="https://github.com/user-attachments/assets/67f6a412-22f1-4066-8c30-7c83588fea13" />

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

Após a instalação do WazuhAIO precisa instalar o agente em outra maquina para monitorar


### Evidência
<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/9d7c4472-a4bc-4323-9e09-cf8a18e8d413" />

<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/bf718c96-3ade-42d8-830a-e15406ce6a49" />

---

## Passo 4 — Ubuntu Server (Alvo Linux)

VM: Ubuntu Server 22.04 | 2 GB RAM | 40 GB | LabNet

```bash
# Configurar IP fixo antes de instalar
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [192.168.100.20/24]
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
  version: 2
```

```bash
sudo netplan apply


```bash
# IP fixo
sudo nano /etc/netplan/00-installer-config.yaml
# addresses: [192.168.100.20/24] | gateway: 192.168.100.1

sudo netplan apply

# Instalar agente Wazuh
# Install the GPG key:
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
# Add the repository:
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
# Update the package information:
apt-get update
# Deploy a Wazuh agent
WAZUH_MANAGER="192.168.100.10" apt-get install wazuh-agent=4.9.2-1
# Enable and start the Wazuh agent service.
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

```

### Evidência

<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/bcd8349f-8642-42ee-88d4-1bd38f6e8f4a" />

<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/4ebbb419-2fb6-47c6-95d9-c86fbf4add0e" />


---

## Passo 5 — Windows Server 2022 (Alvo Windows)

Download: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022

```powershell
# IP fixo
New-NetIPAddress -InterfaceAlias "Ethernet" `
  -IPAddress 192.168.100.30 -PrefixLength 24 `
  -DefaultGateway 192.168.100.1

# Instalar agente Wazuh, Gerar o comando no Dashboard > Deploy new agent

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.100.10' WAZUH_AGENT_NAME='windowsserver'


# Habilitar logs avançados
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

### Evidência

<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/ecf9e2da-dadb-4591-bf33-10b595ab44a1" />
<img width="1563" height="196" alt="Image" src="https://github.com/user-attachments/assets/46652054-ee6d-4fa8-86d7-9811e5914fdf" />
<img width="2559" height="1439" alt="Image" src="https://github.com/user-attachments/assets/bada79ce-7fb5-4704-b1eb-6bab433655db" />

---

## Passo 6 — Kali Linux (Atacante)

VM: Kali Linux | 4 GB RAM | 40 GB | LabNet

```bash
# IP fixo: 192.168.100.50/24
# Atomic Red Team
cd /opt
sudo git clone https://github.com/redcanaryco/atomic-red-team.git
```

### Evidência

<img width="1810" height="1286" alt="Image" src="https://github.com/user-attachments/assets/73a48403-ffa4-4b29-a2ae-80be98e4f2b9" />
---

## Passo 7 — Ubuntu Desktop (Analista)

VM: Ubuntu Desktop 22.04 | 4 GB RAM | 40 GB | LabNet

```bash
# IP fixo: 192.168.100.40/24

# Ferramentas do analista
sudo apt install -y wireshark tshark curl wget git vim

# Acesso ao Wazuh via Firefox
# https://192.168.100.10
```

### Evidência

<img width="1273" height="890" alt="Image" src="https://github.com/user-attachments/assets/4a66a306-0b49-4abc-a08f-c93572d0882d" />
---

## Snapshot — Baseline

Após o setup completo, criar snapshot de cada VM:

```
Nome: "baseline-clean"
Descrição: "Estado inicial — antes de qualquer cenário de ataque"
```

Isso permite resetar o lab após cada exercício.

### Evidência

<img width="1231" height="808" alt="Image" src="https://github.com/user-attachments/assets/e9206f74-7be8-423f-866c-05a07b36124f" />
