# HRD-001 — Hardening Ubuntu Server 22.04 (CIS Benchmark L1/L2)

**Framework:** CIS Ubuntu Linux 22.04 LTS Benchmark v1.0  
**Ambiente:** VM Ubuntu Server no lab / Aplicável a servidores reais  
**Tempo estimado:** 2–3 horas  

---

## Antes de Começar

```bash
# Snapshot ANTES do hardening (sempre!)
# No VMware: VM > Snapshot > Take Snapshot "pre-hardening"

# Verificar versão do SO
lsb_release -a
uname -r

# Criar log de auditoria do hardening
exec > >(tee -a /var/log/hardening-$(date +%F).log) 2>&1
echo "=== Hardening iniciado: $(date) ==="
```

---

## 1. ATUALIZAÇÕES DO SISTEMA

```bash
# 1.1 - Garantir que o sistema está atualizado
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y

# 1.2 - Habilitar atualizações automáticas de segurança
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Verificar configuração
cat /etc/apt/apt.conf.d/20auto-upgrades
```

**✅ Evidência:** `apt list --upgradable` deve retornar vazio após upgrade.

---

## 2. PARTICIONAMENTO E SISTEMA DE ARQUIVOS

```bash
# 2.1 - Verificar partições críticas separadas (recomendado em nova instalação)
df -h
findmnt | grep -E '/tmp|/var|/home'

# 2.2 - Montar /tmp com restrições
sudo systemctl enable tmp.mount
sudo systemctl start tmp.mount

# Adicionar opções restritivas ao /tmp
sudo nano /etc/systemd/system/tmp.mount
# Options=mode=1777,strictatime,noexec,nodev,nosuid

# 2.3 - Desabilitar sistemas de arquivos desnecessários
cat >> /etc/modprobe.d/cis.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

sudo update-initramfs -u
```

---

## 3. SEGURANÇA DO BOOTLOADER

```bash
# 3.1 - Proteger GRUB com senha
sudo grub-mkpasswd-pbkdf2
# (copiar o hash gerado)

sudo nano /etc/grub.d/40_custom
# Adicionar:
# set superusers="admin"
# password_pbkdf2 admin <HASH_COPIADO>

sudo update-grub

# 3.2 - Desabilitar boot de mídia externa (via BIOS/UEFI do hypervisor)
```

---

## 4. PROCESSOS E SERVIÇOS

```bash
# 4.1 - Listar serviços ativos
systemctl list-units --type=service --state=running

# 4.2 - Desabilitar serviços desnecessários
SERVICES_TO_DISABLE=(
  avahi-daemon
  cups
  isc-dhcp-server
  isc-dhcp-server6
  slapd
  nfs-server
  rpcbind
  bind9
  vsftpd
  apache2
  dovecot
  samba
  squid
  snmpd
  rsync
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
  if systemctl is-active --quiet "$svc"; then
    echo "Desabilitando: $svc"
    sudo systemctl stop "$svc"
    sudo systemctl disable "$svc"
  fi
done

# 4.3 - Remover pacotes não necessários
sudo apt purge telnet rsh-client rsh-redone-client talk \
  inetutils-telnetd xinetd nis yp-tools tftpd atftpd \
  tftpd-hpa telnetd rsh-server rsh-redone-server \
  talk talkd -y 2>/dev/null
```

---

## 5. CONFIGURAÇÃO DE REDE

```bash
# 5.1 - Desabilitar IPv6 (se não utilizado)
cat >> /etc/sysctl.d/60-cis-network.conf << 'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

# 5.2 - Hardening de parâmetros de kernel para rede
cat >> /etc/sysctl.d/60-cis-network.conf << 'EOF'
# Desabilitar IP forwarding
net.ipv4.ip_forward = 0

# Desabilitar send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Desabilitar accept redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Desabilitar source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Habilitar proteção SYN flood
net.ipv4.tcp_syncookies = 1

# Habilitar log de pacotes suspeitos
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Habilitar Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Desabilitar resposta a broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Randomizar layout de memória (ASLR)
kernel.randomize_va_space = 2
EOF

sudo sysctl -p /etc/sysctl.d/60-cis-network.conf
```

---

## 6. CONFIGURAÇÃO DO SSH

```bash
# 6.1 - Backup da configuração original
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# 6.2 - Aplicar configurações seguras
sudo tee /etc/ssh/sshd_config.d/99-cis-hardening.conf << 'EOF'
# Protocolo e versão
Protocol 2

# Autenticação
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes

# Limites de sessão
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 60

# Recursos desabilitados
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
GatewayPorts no
PermitTunnel no

# Logs
LogLevel VERBOSE
SyslogFacility AUTH

# Timeout de sessão inativa (15 min)
ClientAliveInterval 900
ClientAliveCountMax 0

# Restrição de usuários (ajustar conforme necessário)
# AllowUsers seu_usuario
# AllowGroups sshusers

# Ciphers e MACs seguros
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
EOF

# Testar configuração antes de reiniciar
sudo sshd -t
sudo systemctl restart sshd

echo "✅ SSH hardening aplicado"
```

---

## 7. CONFIGURAÇÃO DO FIREWALL (UFW)

```bash
# 7.1 - Instalar e configurar UFW
sudo apt install ufw -y

# 7.2 - Política padrão restritiva
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw default deny routed

# 7.3 - Liberar apenas o necessário
sudo ufw allow out 53/udp comment 'DNS'
sudo ufw allow out 80/tcp comment 'HTTP updates'
sudo ufw allow out 443/tcp comment 'HTTPS updates'
sudo ufw allow from 192.168.100.0/24 to any port 22 comment 'SSH da rede do lab'

# 7.4 - Rate limiting em SSH (anti brute force)
sudo ufw limit 22/tcp

sudo ufw enable
sudo ufw status verbose
```

---

## 8. AUDITORIA E LOGS (auditd)

```bash
# 8.1 - Instalar auditd
sudo apt install auditd audispd-plugins -y

# 8.2 - Configurar regras de auditoria (CIS Level 2)
sudo tee /etc/audit/rules.d/99-cis.rules << 'EOF'
# Deletar todas as regras existentes
-D

# Tamanho do buffer
-b 8192

# Falha: panic se buffer cheio (produção) ou log (lab)
-f 1

# Monitorar mudanças em arquivos críticos do sistema
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitorar logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Monitorar execução de comandos privilegiados
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged
-a always,exit -F arch=b32 -S execve -F euid=0 -k privileged

# Monitorar uso de sudo
-w /usr/bin/sudo -p x -k privilege_escalation

# Monitorar modificação de data/hora
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change

# Monitorar escalonamento de privilégios
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
-a always,exit -F arch=b32 -S setuid -S setgid -k priv_esc

# Monitorar netstat e ferramentas de rede
-w /usr/bin/ss -p x -k network_tools
-w /bin/netstat -p x -k network_tools

# Imutável (ninguém pode desabilitar as regras sem reboot)
-e 2
EOF

sudo systemctl enable auditd
sudo systemctl restart auditd
sudo auditctl -l
```

---

## 9. PAM E POLÍTICA DE SENHAS

```bash
# 9.1 - Instalar libpam-pwquality
sudo apt install libpam-pwquality -y

# 9.2 - Configurar política de senha
sudo tee /etc/security/pwquality.conf << 'EOF'
# Tamanho mínimo
minlen = 14

# Complexidade
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1

# Não reutilizar senhas recentes
remember = 5

# Não permitir username na senha
usercheck = 1
EOF

# 9.3 - Configurar bloqueio de conta por tentativas
sudo tee /etc/security/faillock.conf << 'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# 9.4 - Configurar expiração de senhas
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/'  /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
```

---

## 10. CONTROLE DE ACESSO — SUDO E PERMISSÕES

```bash
# 10.1 - Verificar que sudo requer senha
sudo grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# 10.2 - Configurar timeout do sudo (15 min)
echo 'Defaults timestamp_timeout=15' | sudo tee /etc/sudoers.d/timeout

# 10.3 - Verificar permissões em arquivos críticos
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/ssh/sshd_config

# 10.4 - Encontrar arquivos SUID/SGID suspeitos
echo "=== Arquivos SUID ==="
find / -perm -4000 -type f 2>/dev/null | sort

echo "=== Arquivos world-writable ==="
find / -perm -0002 -type f -not -path "/proc/*" 2>/dev/null
```

---

## 11. APPARMOR

```bash
# 11.1 - Verificar que AppArmor está ativo
sudo apparmor_status

# 11.2 - Garantir todos os perfis em enforce mode
sudo aa-enforce /etc/apparmor.d/*

# 11.3 - Verificar perfis
sudo apparmor_status | grep "enforce"
```

---

## 12. FAIL2BAN

```bash
# 12.1 - Instalar e configurar
sudo apt install fail2ban -y

# 12.2 - Configuração customizada
sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime = 3600
EOF

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
sudo fail2ban-client status
```

---

## Verificação Final (Scoring)

```bash
# Instalar e executar CIS-CAT Lite (verificação automática)
# Download: https://www.cisecurity.org/cis-benchmarks/

# Verificação manual rápida
echo "=== Resumo do Hardening ==="
echo "SSH Root Login:"
sudo grep -i "PermitRootLogin" /etc/ssh/sshd_config*

echo "Password Auth SSH:"
sudo grep -i "PasswordAuthentication" /etc/ssh/sshd_config*

echo "UFW Status:"
sudo ufw status

echo "Auditd Status:"
sudo systemctl is-active auditd

echo "Fail2ban Status:"
sudo fail2ban-client status sshd 2>/dev/null

echo "AppArmor:"
sudo apparmor_status | head -5

echo "=== Hardening concluído: $(date) ==="
```

---

## Checklist Final

- [ ] Sistema atualizado
- [ ] Serviços desnecessários desabilitados
- [ ] Parâmetros kernel endurecidos (sysctl)
- [ ] SSH configurado (sem root, sem senha, ciphers seguros)
- [ ] UFW ativo com política default deny
- [ ] auditd configurado com regras CIS
- [ ] Política de senhas aplicada (pwquality + faillock)
- [ ] fail2ban ativo no SSH
- [ ] AppArmor em enforce mode
- [ ] Permissões de arquivos críticos verificadas
- [ ] Snapshot "pós-hardening" criado

---

## Referências
- [CIS Ubuntu Linux 22.04 Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [STIG Ubuntu 20.04](https://public.cyber.mil/stigs/downloads/)
- [Lynis — audit tool](https://cisofy.com/lynis/)
