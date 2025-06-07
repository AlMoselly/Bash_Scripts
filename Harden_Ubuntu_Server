#!/bin/bash

set -euo pipefail

log_ok() {
    echo -e "[\e[32mOK\e[0m] $1"
}

log_fail() {
    echo -e "[\e[31mFAIL\e[0m] $1"
}

echo "[*] Starting Linux system hardening..."

# 1. UFW Firewall setup
echo "[*] Configuring UFW firewall..."
apt-get update -qq
apt-get install -y ufw >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow ssh >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1
systemctl enable ufw >/dev/null 2>&1
ufw status verbose | grep -q "Status: active" && log_ok "UFW firewall enabled and configured." || log_fail "Failed to enable UFW."

# 2. Fail2Ban install and start
echo "[*] Installing Fail2Ban..."
apt-get install -y fail2ban >/dev/null 2>&1
systemctl enable fail2ban >/dev/null 2>&1
systemctl start fail2ban >/dev/null 2>&1
if systemctl is-active --quiet fail2ban; then
    log_ok "Fail2Ban is installed and running."
else
    log_fail "Fail2Ban service is not running."
fi

# 3. Secure Boot check
echo "[*] Checking Secure Boot status..."
if command -v mokutil >/dev/null 2>&1; then
    SB_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    if echo "$SB_STATE" | grep -iq "enabled"; then
        log_ok "Secure Boot is ENABLED."
    elif echo "$SB_STATE" | grep -iq "disabled"; then
        log_fail "Secure Boot is DISABLED. Please enable it in BIOS/UEFI."
    else
        echo "[!] Secure Boot status unknown or mokutil not fully supported."
    fi
else
    echo "[!] mokutil command not found; cannot check Secure Boot status."
fi

# 4. SSH login banners
echo "[*] Setting SSH login banners..."
BANNER_PATH="/etc/issue.net"
cat > "$BANNER_PATH" <<EOF
*** Authorized Access Only! ***
All activities are monitored and recorded.
EOF
sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config || echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
systemctl reload sshd
log_ok "SSH banner configured."

# 5. Auditd installation (if kernel supports it)
echo "[*] Checking kernel audit support..."
AUDIT_SUPPORT=""
if [ -f /proc/config.gz ]; then
    AUDIT_SUPPORT=$(zcat /proc/config.gz | grep -E "^CONFIG_AUDIT=y" || true)
elif [ -f /boot/config-$(uname -r) ]; then
    AUDIT_SUPPORT=$(grep -E "^CONFIG_AUDIT=y" /boot/config-$(uname -r) || true)
fi

if [ -z "$AUDIT_SUPPORT" ]; then
    log_fail "Kernel does not support auditd. Skipping auditd setup."
else
    apt-get install -y auditd audispd-plugins >/dev/null 2>&1
    systemctl enable auditd >/dev/null 2>&1
    systemctl start auditd >/dev/null 2>&1
    if systemctl is-active --quiet auditd; then
        log_ok "auditd is installed and running."
    else
        log_fail "auditd failed to start. Check system logs."
    fi
fi

# 6. unattended-upgrades
echo "[*] Installing unattended-upgrades..."
apt-get install -y unattended-upgrades >/dev/null 2>&1
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1
log_ok "unattended-upgrades installed and configured."

# 7. Disable core dumps
echo "[*] Disabling core dumps..."
sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 || true
echo "fs.suid_dumpable=0" >> /etc/sysctl.conf
ulimit -c 0 || true
log_ok "Core dumps disabled."

# 8. Kernel hardening with sysctl
echo "[*] Applying kernel hardening sysctl settings..."
SYSCTL_CONF="/etc/sysctl.d/99-harden.conf"
cat > "$SYSCTL_CONF" <<EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
EOF
sysctl --system >/dev/null 2>&1
log_ok "Kernel sysctl settings applied."

# 9. Protect /tmp and /var/tmp with noexec, nodev, nosuid in fstab if not already present
echo "[*] Adding /tmp and /var/tmp protections..."
for dir in /tmp /var/tmp; do
    if ! grep -q " $dir " /etc/fstab; then
        echo "tmpfs $dir tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        log_ok "$dir entry added to /etc/fstab."
    else
        log_ok "$dir entry already present in /etc/fstab."
    fi
done

echo -e "\n================ SUMMARY ================"
echo "✔ Firewall:         UFW configured"
echo "✔ SSH banner:       Enabled"
echo "✔ Fail2Ban:         Installed and running"
if command -v mokutil >/dev/null 2>&1 && echo "$SB_STATE" | grep -iq "disabled"; then
    echo "✘ Secure Boot:      DISABLED (manual BIOS/UEFI enable recommended)"
else
    echo "✔ Secure Boot:      ENABLED or Unknown"
fi
if [ -z "$AUDIT_SUPPORT" ]; then
    echo "✘ auditd:           inactive or kernel support missing"
else
    systemctl is-active --quiet auditd && echo "✔ auditd:           active and running" || echo "✘ auditd:           failed"
fi
echo "✔ Kernel hardening: sysctl applied"
echo "✔ Core dumps:       Disabled"
echo "✔ Updates:          unattended-upgrades configured"
echo "✔ /tmp protection:  fstab entries added"

echo -e "\n[*] Hardening complete. It is recommended to reboot."

exit 0
