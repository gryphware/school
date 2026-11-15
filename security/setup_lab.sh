#!/bin/bash
#
# setup_lab.sh - Script hỗ trợ setup lab Tấn công/Phòng thủ (Red Team/Blue Team)
# Chỉ dùng trong môi trường lab được cấp phép, KHÔNG dùng để tấn công hệ thống
# không thuộc quyền sở hữu hoặc chưa được phép kiểm thử.
#
# Yêu cầu: chạy với quyền root (sudo ./setup_lab.sh)

set -e

# ---------- Màu sắc cho đẹp terminal ----------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[ERR ]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
   log_err "Script này cần chạy với quyền root. Hãy chạy: sudo $0"
   exit 1
fi

# ---------- Cài whiptail nếu chưa có (để hiện hộp thoại hỏi) ----------
if ! command -v whiptail &> /dev/null; then
    log_info "Chưa có whiptail, đang cài đặt..."
    if command -v apt &> /dev/null; then
        apt update -y && apt install -y whiptail
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm libnewt
    fi
fi

# ---------- Bước 1: Hỏi distro ----------
DISTRO_CHOICE=$(whiptail --title "Chọn Distro" --menu "Bạn đang dùng Linux distro nào?" 15 50 2 \
    "1" "Arch Linux" \
    "2" "Ubuntu / Debian" 3>&1 1>&2 2>&3)

case "$DISTRO_CHOICE" in
    1) DISTRO="arch" ;;
    2) DISTRO="ubuntu" ;;
    *) log_err "Không chọn gì, thoát."; exit 1 ;;
esac

log_info "Distro đã chọn: $DISTRO"

# ---------- Hàm cài gói theo distro ----------
install_pkg() {
    local pkgs="$@"
    if [[ "$DISTRO" == "arch" ]]; then
        pacman -Sy --noconfirm $pkgs
    else
        apt update -y
        apt install -y $pkgs
    fi
}

# ---------- Bước 2: Hỏi vai trò ----------
ROLE_CHOICE=$(whiptail --title "Chọn vai trò" --menu "Bạn muốn đóng vai trò nào trong lab?" 15 55 2 \
    "1" "Tấn công (Attacker)" \
    "2" "Phòng thủ (Defender)" 3>&1 1>&2 2>&3)

case "$ROLE_CHOICE" in
    1) ROLE="attacker" ;;
    2) ROLE="defender" ;;
    *) log_err "Không chọn gì, thoát."; exit 1 ;;
esac

log_info "Vai trò đã chọn: $ROLE"

# ---------- Bước 2b: Nếu là Defender, hỏi dùng firewall nào ----------
FIREWALL=""
if [[ "$ROLE" == "defender" ]]; then
    FW_CHOICE=$(whiptail --title "Chọn Firewall" --menu "Bạn muốn dùng firewall nào để phòng thủ?" 15 55 2 \
        "1" "ufw (đơn giản, khuyến nghị cho người mới)" \
        "2" "iptables (nâng cao, tùy biến sâu)" 3>&1 1>&2 2>&3)

    case "$FW_CHOICE" in
        1) FIREWALL="ufw" ;;
        2) FIREWALL="iptables" ;;
        *) log_err "Không chọn gì, thoát."; exit 1 ;;
    esac
    log_info "Firewall đã chọn: $FIREWALL"
fi

# =========================================================
#                    PHẦN TẤN CÔNG (ATTACKER)
# =========================================================
setup_attacker() {
    log_info "Cài đặt các công cụ kiểm thử mạng cơ bản cho máy Attacker..."

    if [[ "$DISTRO" == "arch" ]]; then
        install_pkg hping3 nmap
    else
        install_pkg hping3 nmap
    fi

    log_warn "Lưu ý: hping3 và nmap chỉ nên dùng trong môi trường lab được cấp phép"
    log_warn "hoặc nhắm vào hệ thống bạn sở hữu/được phép kiểm thử."
    log_info "Đã cài xong hping3 và nmap. Bạn tự cấu hình tham số theo kịch bản lab của mình."
}

# =========================================================
#                   PHẦN PHÒNG THỦ (DEFENDER)
# =========================================================

install_defender_pkgs() {
    log_info "Cài đặt các gói phòng thủ (firewall: $FIREWALL)..."

    local fw_pkg="iptables"
    [[ "$FIREWALL" == "ufw" ]] && fw_pkg="ufw"

    if [[ "$DISTRO" == "arch" ]]; then
        install_pkg "$fw_pkg" fail2ban audit net-tools
    else
        install_pkg "$fw_pkg" fail2ban auditd net-tools
    fi
    systemctl enable --now auditd
}

# 3.1 Chống DDoS (SYN flood / ICMP flood kiểu hping3)
setup_anti_ddos_iptables() {
    # Giới hạn tốc độ gói SYN mới - chặn SYN flood
    iptables -N SYN_FLOOD 2>/dev/null || iptables -F SYN_FLOOD
    iptables -A INPUT -p tcp --syn -j SYN_FLOOD
    iptables -A SYN_FLOOD -m limit --limit 5/s --limit-burst 10 -j RETURN
    iptables -A SYN_FLOOD -j DROP

    # Giới hạn ICMP (ping flood)
    iptables -N ICMP_FLOOD 2>/dev/null || iptables -F ICMP_FLOOD
    iptables -A INPUT -p icmp --icmp-type echo-request -j ICMP_FLOOD
    iptables -A ICMP_FLOOD -m limit --limit 1/s --limit-burst 5 -j RETURN
    iptables -A ICMP_FLOOD -j DROP

    # Drop gói bất thường (common trong flood/scan)
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
}

setup_anti_ddos_ufw() {
    local rules="/etc/ufw/before.rules"
    cp "$rules" "${rules}.bak.$(date +%s)"

    # Chỉ chèn 1 lần nếu chưa có
    if ! grep -q "ufw-synflood" "$rules"; then
        # Khai báo chain mới ngay sau chain ufw-not-local
        sed -i '/:ufw-not-local - \[0:0\]/a :ufw-synflood - [0:0]\n:ufw-icmpflood - [0:0]' "$rules"

        # Chèn luật trước dòng COMMIT cuối cùng của khối *filter
        sed -i '0,/^COMMIT/{/^COMMIT/i\
# --- Anti-DDoS rules (added by setup_lab.sh) ---\
-A ufw-before-input -p tcp --syn -j ufw-synflood\
-A ufw-synflood -m limit --limit 5/s --limit-burst 10 -j RETURN\
-A ufw-synflood -j DROP\
-A ufw-before-input -p icmp --icmp-type echo-request -j ufw-icmpflood\
-A ufw-icmpflood -m limit --limit 1/s --limit-burst 5 -j RETURN\
-A ufw-icmpflood -j DROP\
-A ufw-before-input -p tcp --tcp-flags ALL NONE -j DROP\
-A ufw-before-input -p tcp --tcp-flags ALL ALL -j DROP\
-A ufw-before-input -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP\
-A ufw-before-input -p tcp --tcp-flags SYN,RST SYN,RST -j DROP\
# --- End anti-DDoS rules ---
}' "$rules"
    fi
}

setup_anti_ddos() {
    log_info "[3.1] Thiết lập chống DDoS (SYN flood / ICMP flood) với $FIREWALL..."
    if [[ "$FIREWALL" == "ufw" ]]; then
        setup_anti_ddos_ufw
    else
        setup_anti_ddos_iptables
    fi
    log_info "Đã thiết lập giới hạn tốc độ SYN/ICMP để giảm thiểu DDoS."
}

# 3.2 Né quét nmap - mặc định DROP thay vì REJECT
setup_anti_scan_iptables() {
    # Chính sách mặc định: DROP tất cả inbound, cho phép outbound
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Cho phép loopback và kết nối đã thiết lập
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Cho phép SSH (để không tự khóa mình ra khỏi máy) - nên giới hạn port/IP sau
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
}

setup_anti_scan_ufw() {
    # Policy mặc định: deny incoming, allow outgoing (tương đương DROP)
    ufw default deny incoming
    ufw default allow outgoing

    # Giữ SSH mở để không tự khóa mình
    ufw allow 22/tcp

    # Comment các rule ACCEPT ping/icmp mặc định của ufw để né bị
    # nmap/ping phát hiện máy đang "sống" qua ICMP echo
    local rules="/etc/ufw/before.rules"
    sed -i 's/^-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/#&/' "$rules"
    sed -i 's/^-A ufw-before-input -p icmp --icmp-type timestamp-request -j ACCEPT/#&/' "$rules"

    ufw --force enable
}

setup_anti_scan() {
    log_info "[3.2] Thiết lập policy mặc định DROP/DENY để tránh bị nmap quét dễ dàng ($FIREWALL)..."
    if [[ "$FIREWALL" == "ufw" ]]; then
        setup_anti_scan_ufw
    else
        setup_anti_scan_iptables
    fi
    log_warn "Đã set policy DROP/DENY mặc định. Nhớ đảm bảo SSH (port 22) vẫn mở"
    log_warn "để không tự khóa quyền truy cập từ xa của chính bạn."
}

# 3.3 Chống brute force SSH bằng fail2ban (3 lần sai -> ban)
setup_fail2ban_ssh() {
    log_info "[3.3] Cấu hình fail2ban chống brute force SSH (banaction: $FIREWALL)..."

    local logpath="/var/log/auth.log"
    if [[ "$DISTRO" == "arch" ]]; then
        logpath="systemd"
    fi

    local banaction="iptables-multiport"
    [[ "$FIREWALL" == "ufw" ]] && banaction="ufw"

    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime   = 3600
findtime  = 300
maxretry  = 3
banaction = $banaction

[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 3
bantime  = 3600
findtime = 300
EOF

    if [[ "$DISTRO" == "arch" ]]; then
        sed -i '/^\[sshd\]/a backend = systemd' /etc/fail2ban/jail.local
    else
        sed -i "/^\[sshd\]/a logpath  = $logpath" /etc/fail2ban/jail.local
    fi

    systemctl enable --now fail2ban
    systemctl restart fail2ban

    log_info "fail2ban đã bật: sai mật khẩu SSH quá 3 lần trong 5 phút -> ban 1 giờ."
    log_info "Kiểm tra trạng thái: fail2ban-client status sshd"

    show_fail2ban_result
}

# Hiển thị kết quả/trạng thái ban hiện tại của jail sshd, và tùy chọn theo dõi real-time
show_fail2ban_result() {
    sleep 1  # chờ fail2ban khởi động hẳn trước khi query status

    local status
    status=$(fail2ban-client status sshd 2>&1)

    log_info "---- Trạng thái jail sshd (fail2ban) ----"
    echo "$status"
    log_info "------------------------------------------"

    if command -v whiptail &> /dev/null; then
        whiptail --title "Trạng thái fail2ban - sshd" --msgbox "$status" 15 60
    fi

    if whiptail --title "Theo dõi real-time" \
        --yesno "Bạn có muốn theo dõi IP bị ban theo thời gian thực không?\n(Nhấn Ctrl+C để thoát theo dõi)" 10 60; then
        clear
        log_info "Đang theo dõi log fail2ban (sẽ in ra khi có IP mới bị Ban/Unban)..."
        log_info "Nhấn Ctrl+C để dừng theo dõi và tiếp tục script."
        journalctl -u fail2ban -f --no-pager | grep --line-buffered -E "Ban|Unban" || true
    fi
}

# 3.4 Chặn 1 IP cụ thể
setup_block_ip() {
    local target_ip
    target_ip=$(whiptail --title "Chặn IP" --inputbox "Nhập IP muốn chặn (để trống để bỏ qua bước này):" 10 50 3>&1 1>&2 2>&3) || true

    if [[ -z "$target_ip" ]]; then
        log_warn "Không nhập IP, bỏ qua bước chặn IP."
        return
    fi

    if [[ "$FIREWALL" == "ufw" ]]; then
        ufw insert 1 deny from "$target_ip" to any
    else
        iptables -I INPUT -s "$target_ip" -j DROP
    fi
    log_info "[3.4] Đã chặn mọi traffic đến từ IP: $target_ip"
}

save_rules() {
    if [[ "$FIREWALL" == "ufw" ]]; then
        log_info "ufw tự lưu rules vào /etc/ufw/, reload lại để áp dụng thay đổi trong before.rules..."
        ufw reload
    else
        log_info "Lưu rules iptables để không mất sau khi reboot..."
        if [[ "$DISTRO" == "arch" ]]; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/iptables.rules
            systemctl enable --now iptables 2>/dev/null || true
        else
            install_pkg iptables-persistent
            iptables-save > /etc/iptables/rules.v4
        fi
    fi
}

setup_defender() {
    install_defender_pkgs
    setup_anti_ddos
    setup_anti_scan
    setup_fail2ban_ssh
    setup_block_ip
    save_rules

    log_info "=========================================="
    log_info " Setup PHÒNG THỦ hoàn tất! (Firewall: $FIREWALL)"
    log_info " - Chống DDoS (SYN/ICMP flood): OK"
    log_info " - Policy DROP/DENY mặc định (né nmap): OK"
    log_info " - fail2ban chống brute force SSH (3 lần sai): OK"
    log_info " - Chặn IP tùy chỉnh: OK (nếu đã nhập)"
    log_info "=========================================="
}

# ---------- Thực thi theo vai trò ----------
if [[ "$ROLE" == "attacker" ]]; then
    setup_attacker
else
    setup_defender
fi

log_info "Hoàn tất script. Kiểm tra log ở trên để xác nhận các bước đã chạy đúng."
