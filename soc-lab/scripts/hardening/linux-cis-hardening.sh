#!/usr/bin/env bash
# =============================================================================
# linux-cis-hardening.sh
# Automação de hardening CIS Benchmark L1 — Ubuntu Server 22.04
# Uso: sudo bash linux-cis-hardening.sh [--dry-run]
# =============================================================================

set -euo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

LOG="/var/log/cis-hardening-$(date +%F_%H%M).log"
PASS=0; FAIL=0; SKIP=0

# Cores
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log() { echo -e "$1" | tee -a "$LOG"; }
pass() { ((PASS++)); log "${GREEN}[PASS]${NC} $1"; }
fail() { ((FAIL++)); log "${RED}[FAIL]${NC} $1"; }
info() { log "${BLUE}[INFO]${NC} $1"; }
warn() { log "${YELLOW}[WARN]${NC} $1"; }

run() {
  if $DRY_RUN; then
    warn "[DRY-RUN] $*"
  else
    eval "$@" >> "$LOG" 2>&1 && pass "$*" || fail "$*"
  fi
}

# Verificar root
[[ $EUID -ne 0 ]] && { echo "Execute como root: sudo $0"; exit 1; }

log "======================================================"
log " CIS Ubuntu 22.04 Hardening — $(date)"
log " Modo: $(if $DRY_RUN; then echo 'DRY-RUN'; else echo 'LIVE'; fi)"
log "======================================================"

# ─────────────────────────────────────────────
# 1. ATUALIZAÇÕES
# ─────────────────────────────────────────────
info "=== 1. Atualizações do Sistema ==="
run "apt-get update -y"
run "apt-get upgrade -y"
run "apt-get install -y unattended-upgrades"

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
pass "Atualizações automáticas configuradas"

# ─────────────────────────────────────────────
# 2. MÓDULOS DESNECESSÁRIOS
# ─────────────────────────────────────────────
info "=== 2. Módulos de Sistema de Arquivos ==="
DISABLED_FS=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf)
for fs in "${DISABLED_FS[@]}"; do
  echo "install $fs /bin/true" >> /etc/modprobe.d/cis.conf
  rmmod "$fs" 2>/dev/null || true
  pass "Módulo desabilitado: $fs"
done
run "update-initramfs -u"

# ─────────────────────────────────────────────
# 3. PARÂMETROS DE KERNEL (SYSCTL)
# ─────────────────────────────────────────────
info "=== 3. Parâmetros de Kernel ==="
cat > /etc/sysctl.d/60-cis-hardening.conf << 'EOF'
# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Proteção SYN
net.ipv4.tcp_syncookies = 1

# Log de pacotes suspeitos
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignorar broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ASLR
kernel.randomize_va_space = 2

# Proteção dmesg
kernel.dmesg_restrict = 1

# Ocultar ponteiros do kernel
kernel.kptr_restrict = 2

# Desabilitar SysRq
kernel.sysrq = 0

# Proteger links simbólicos
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF

run "sysctl -p /etc/sysctl.d/60-cis-hardening.conf"

# ─────────────────────────────────────────────
# 4. SERVIÇOS DESNECESSÁRIOS
# ─────────────────────────────────────────────
info "=== 4. Desabilitando Serviços Desnecessários ==="
DISABLE_SERVICES=(
  avahi-daemon
  cups
  isc-dhcp-server
  nfs-server
  rpcbind
  bind9
  vsftpd
  apache2
  nginx
  dovecot
  samba
  squid
  snmpd
  xinetd
)

for svc in "${DISABLE_SERVICES[@]}"; do
  if systemctl list-unit-files | grep -q "^${svc}"; then
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    pass "Serviço desabilitado: $svc"
  else
    info "Serviço não encontrado (ok): $svc"
  fi
done

# ─────────────────────────────────────────────
# 5. SSH HARDENING
# ─────────────────────────────────────────────
info "=== 5. SSH Hardening ==="
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak."$(date +%F)"

cat > /etc/ssh/sshd_config.d/99-cis.conf << 'EOF'
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 60
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
GatewayPorts no
PermitTunnel no
LogLevel VERBOSE
SyslogFacility AUTH
ClientAliveInterval 900
ClientAliveCountMax 0
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
EOF

sshd -t && run "systemctl restart sshd"

# ─────────────────────────────────────────────
# 6. FIREWALL (UFW)
# ─────────────────────────────────────────────
info "=== 6. Firewall UFW ==="
run "apt-get install -y ufw"
run "ufw --force reset"
run "ufw default deny incoming"
run "ufw default deny outgoing"
run "ufw allow out 53/udp"
run "ufw allow out 80/tcp"
run "ufw allow out 443/tcp"
run "ufw limit 22/tcp"
echo "y" | ufw enable
pass "UFW configurado e ativo"

# ─────────────────────────────────────────────
# 7. AUDITD
# ─────────────────────────────────────────────
info "=== 7. Auditoria (auditd) ==="
run "apt-get install -y auditd audispd-plugins"

cat > /etc/audit/rules.d/99-cis.rules << 'EOF'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged
-a always,exit -F arch=b32 -S execve -F euid=0 -k privileged
-w /usr/bin/sudo -p x -k priv_esc
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
-e 2
EOF

run "systemctl enable auditd"
run "systemctl restart auditd"

# ─────────────────────────────────────────────
# 8. PAM — POLÍTICA DE SENHAS
# ─────────────────────────────────────────────
info "=== 8. PAM / Política de Senhas ==="
run "apt-get install -y libpam-pwquality"

cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
remember = 5
usercheck = 1
EOF

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/'  /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
pass "Política de senhas configurada"

# ─────────────────────────────────────────────
# 9. FAIL2BAN
# ─────────────────────────────────────────────
info "=== 9. Fail2ban ==="
run "apt-get install -y fail2ban"

cat > /etc/fail2ban/jail.local << 'EOF'
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
EOF

run "systemctl enable fail2ban"
run "systemctl restart fail2ban"

# ─────────────────────────────────────────────
# 10. APPARMOR
# ─────────────────────────────────────────────
info "=== 10. AppArmor ==="
run "apt-get install -y apparmor apparmor-utils"
run "systemctl enable apparmor"
run "systemctl start apparmor"
aa-enforce /etc/apparmor.d/* 2>/dev/null || true
pass "AppArmor em enforce mode"

# ─────────────────────────────────────────────
# RELATÓRIO FINAL
# ─────────────────────────────────────────────
log ""
log "======================================================"
log " RELATÓRIO DE HARDENING — $(date)"
log "======================================================"
log " ${GREEN}PASS: $PASS${NC}"
log " ${RED}FAIL: $FAIL${NC}"
log " ${YELLOW}SKIP: $SKIP${NC}"
log " Log completo: $LOG"
log "======================================================"

if [[ $FAIL -gt 0 ]]; then
  warn "Existem $FAIL falhas. Revisar o log: $LOG"
  exit 1
fi
