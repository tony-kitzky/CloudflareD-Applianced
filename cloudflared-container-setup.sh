#!/usr/bin/env bash
#------------------------------------------------------------------------------
# cloudflared-container-setup.sh
# Setup environment on Alma Linux 9 server to run rootless container for
#  CloudflareD tunnel daemon.
#
# Vibe coded with Cloude Sonet 4.6 on July 27, 2026.
#   -- https://www.perplexity.ai/search/914c5f0b-13c3-4605-a520-7f495d7792b9
#
# Implements:
#  1) Install packages: podman, passt
#  2) Prompt for:
#      a) username to run rootless cloudflared (create if missing) -- default: cloudflared
#      b) cloudflared image tag
#      c) cloudflared tunnel token (dashboard-generated)
#      d) whether server uses 1 NIC or 2 NICs
#      e) OPTIONAL: enable policy routing for dual-NIC origin traffic via eth1
#  3) Enable persistent journaling + per-user journals
#  4) Enable boot-start for user services (linger) for the cloudflared user
#  5) Write /etc/sysctl.d/99-cloudflared.conf to update system limits for ping users and udp socket buffers
#  6) OPTIONAL policy routing if 2 NICs and enabled:
#      - default remains on eth0
#      - route-table "origin" created in /etc/iproute2/rt_tables
#      - RFC1918 prefixes via eth1 in route-table origin
#      - rule to lookup traffic sourced from the eth1 IPv4 address
#      - persistence via /etc/sysconfig/network-scripts/route-eth1 and rule-eth1
#  7) Pull cloudflared image (fully-qualified docker.io/cloudflare/cloudflared:<tag>)
#  8) Create Quadlet base + drop-ins
#  9) Start the cloudflared.service (systemd --user) for the selected user
# 10) Install /usr/local/sbin/cloudflared-container management command
#     (menu-driven status/restart/upgrade tool; usable by any sudoer)
# 11) Write /etc/profile.d/cloudflare-alias.sh
#
# Notes:
#  - Token is stored on disk in a drop-in file (0600). Protect the user account.
#  - Rootless systemd user services require a working user runtime dir; the script
#    sets XDG_RUNTIME_DIR to avoid "Failed to connect to bus: No medium found".
#
# Usage:
#   sudo bash cloudflared-container-setup.sh
#------------------------------------------------------------------------------

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*" >&2; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"; }

iface_exists() { ip link show dev "$1" >/dev/null 2>&1; }

user_exists() { id "$1" >/dev/null 2>&1; }

ensure_user() {
  local u="$1"
  if user_exists "$u"; then
    info "User exists: $u"
  else
    info "User does not exist, creating: $u"
    useradd -m -s /bin/bash "$u"
  fi
  ensure_subuid_subgid "$u"
}

user_uid() { id -u "$1"; }

# Ensure a user has subuid/subgid ranges allocated for rootless Podman.
# Handles both newly created and pre-existing users. useradd normally
# allocates these automatically via /etc/login.defs for new accounts, but
# pre-existing accounts (the user_exists branch above) are never verified,
# which can cause confusing rootless Podman failures later.
ensure_subuid_subgid() {
  local u="$1"
  local need_subuid=1 need_subgid=1

  grep -Eq "^${u}:" /etc/subuid 2>/dev/null && need_subuid=0
  grep -Eq "^${u}:" /etc/subgid 2>/dev/null && need_subgid=0

  if [[ "$need_subuid" -eq 0 && "$need_subgid" -eq 0 ]]; then
    info "subuid/subgid already allocated for user: $u"
    return 0
  fi

  info "Allocating missing subuid/subgid range(s) for user: $u"
  if command -v usermod >/dev/null 2>&1; then
    usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$u" 2>/dev/null || true
  fi

  grep -Eq "^${u}:" /etc/subuid 2>/dev/null || echo "${u}:100000:65536" >> /etc/subuid
  grep -Eq "^${u}:" /etc/subgid 2>/dev/null || echo "${u}:100000:65536" >> /etc/subgid

  grep -Eq "^${u}:" /etc/subuid 2>/dev/null || die "Failed to allocate subuid range for user: $u"
  grep -Eq "^${u}:" /etc/subgid 2>/dev/null || die "Failed to allocate subgid range for user: $u"

  info "subuid/subgid ranges confirmed for user: $u (run 'podman system migrate' as $u if the service already ran before this change)"
}

get_ipv4_addr_for_dev() {
  local dev="$1"
  ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
}

# Run systemctl --user for a given user in non-interactive contexts.
user_systemctl() {
  local u="$1"; shift
  local uid; uid="$(user_uid "$u")"

  mkdir -p "/run/user/${uid}"
  chown "${uid}:${uid}" "/run/user/${uid}"
  chmod 0700 "/run/user/${uid}"

  sudo -u "$u" env XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user "$@"
}

install_packages() {
  info "Installing packages: podman, passt"
  dnf install -y podman passt >/dev/null
}

enable_persistent_journaling() {
  info "Enabling persistent journaling and per-user journals (SplitMode=uid)"

  mkdir -p /var/log/journal
  chmod 2755 /var/log/journal

  mkdir -p /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/99-persistent.conf <<'EOF'
[Journal]
Storage=persistent
SplitMode=uid
EOF

  systemctl restart systemd-journald.service
  journalctl --flush >/dev/null 2>&1 || true
}

enable_linger_for_user() {
  local u="$1"
  info "Enabling linger (boot-start for systemd --user) for user: $u"
  loginctl enable-linger "$u"
}

write_sysctl_cloudflared() {
  info "Writing /etc/sysctl.d/99-cloudflared.conf"

  cat >/etc/sysctl.d/99-cloudflared.conf <<'EOF'
# Cloudflared ICMP proxy enablement and QUIC UDP socket buffer ceilings.

# Allow the cloudflared container's nonroot group (65532) to create ICMP echo sockets.
net.ipv4.ping_group_range = 0 65532
net.ipv6.ping_group_range = 0 65532

# QUIC UDP socket buffer ceilings (helps avoid quic-go UDP buffer warnings).
net.core.rmem_max = 8000000
net.core.wmem_max = 8000000
EOF

  sysctl --system >/dev/null
}

configure_policy_routing_two_nic() {
  local eth1_ip="$1"
  local rt_name="origin"
  local rt_id="100"
  local rt_tables_file="/etc/iproute2/rt_tables"
  local rules_file="/etc/sysconfig/network-scripts/rule-eth1"
  local routes_file="/etc/sysconfig/network-scripts/route-eth1"

  info "Configuring policy routing for dual-NIC host using route table '${rt_name}' from source ${eth1_ip}"

  if command -v nmcli >/dev/null 2>&1; then
    local con1
    con1="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: '$2=="eth1" {print $1; exit}')"
    if [[ -n "$con1" ]]; then
      info "Removing IPv4 gateway from NetworkManager profile for eth1: ${con1}"
      nmcli con mod "$con1" ipv4.never-default yes >/dev/null 2>&1 || true
      nmcli con mod "$con1" -ipv4.gateway >/dev/null 2>&1 || true
    fi
  fi

  grep -Eq "^[[:space:]]*${rt_id}[[:space:]]+${rt_name}(\\s|$)" "$rt_tables_file" 2>/dev/null || \
    echo "${rt_id} ${rt_name}" >> "$rt_tables_file"

  ip route replace 10.0.0.0/8 dev eth1 table "$rt_name"
  ip route replace 172.16.0.0/12 dev eth1 table "$rt_name"
  ip route replace 192.168.0.0/16 dev eth1 table "$rt_name"

  ip rule del from "$eth1_ip/32" table "$rt_name" 2>/dev/null || true
  ip rule add from "$eth1_ip/32" table "$rt_name" priority 100

  mkdir -p /etc/sysconfig/network-scripts
  cat >"$routes_file" <<EOF
10.0.0.0/8 dev eth1 table ${rt_name}
172.16.0.0/12 dev eth1 table ${rt_name}
192.168.0.0/16 dev eth1 table ${rt_name}
EOF

  cat >"$rules_file" <<EOF
from ${eth1_ip}/32 table ${rt_name} priority 100
EOF

  info "Policy routing sanity check:"
  ip rule show | sed 's/^/  /'
  ip route show table "$rt_name" | sed 's/^/  /'
  ip route get 10.1.2.3 from "$eth1_ip" | sed 's/^/  /' || true
}

pull_cloudflared_image_rootless() {
  local u="$1" tag="$2"
  local homedir
  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || die "Could not determine home directory for user: $u"

  info "Pulling image as rootless user $u: docker.io/cloudflare/cloudflared:${tag}"
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman pull 'docker.io/cloudflare/cloudflared:${tag}'"
}

install_management_command() {
  local install_path="/usr/local/sbin/cloudflared-container"

  info "Installing cloudflared-container management command to: ${install_path}"

  cat >"${install_path}" <<'MANAGE_SCRIPT_EOF'
#!/usr/bin/env bash
#------------------------------------------------------------------------------
# cloudflared-container
# Menu-driven management tool for the rootless "cloudflared-container"
# Podman Quadlet deployment created by cloudflared-container-setup.sh.
#
# Must be run with sudo/root. Internally switches to the cloudflared user's
# systemd --user session via XDG_RUNTIME_DIR so any sudoer can manage the
# container without needing to log in as that user directly.
#
# Usage:
#   sudo cloudflared-container
#------------------------------------------------------------------------------

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*" >&2; }
warn() { echo "WARN: $*" >&2; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo cloudflared-container"; }

user_exists() { id "$1" >/dev/null 2>&1; }

user_uid() { id -u "$1"; }

user_home() { getent passwd "$1" | awk -F: '{print $6}'; }

# Run systemctl --user for a given user, setting XDG_RUNTIME_DIR so that
# any sudo-privileged caller (not just the cloudflared user itself) can
# reach that user's systemd --user session and manage the container.
user_systemctl() {
  local u="$1"; shift
  local uid; uid="$(user_uid "$u")"
  local runtime_dir="/run/user/${uid}"

  if [[ ! -d "$runtime_dir" ]]; then
    mkdir -p "$runtime_dir"
    chown "${uid}:${uid}" "$runtime_dir"
    chmod 0700 "$runtime_dir"
  fi

  sudo -u "$u" env XDG_RUNTIME_DIR="$runtime_dir" systemctl --user "$@"
}

# Run an arbitrary command as the cloudflared user with XDG_RUNTIME_DIR set,
# e.g. for podman commands that talk to the user's rootless Podman socket.
user_run() {
  local u="$1"; shift
  local uid; uid="$(user_uid "$u")"
  local runtime_dir="/run/user/${uid}"
  local homedir; homedir="$(user_home "$u")"

  if [[ ! -d "$runtime_dir" ]]; then
    mkdir -p "$runtime_dir"
    chown "${uid}:${uid}" "$runtime_dir"
    chmod 0700 "$runtime_dir"
  fi

  sudo -H -u "$u" env XDG_RUNTIME_DIR="$runtime_dir" bash -lc "cd '$homedir' && $*"
}

# Try to auto-detect the user running the cloudflared Quadlet service by
# scanning systemd --user sessions for anyone with a cloudflared.service
# unit loaded. Falls back to "cloudflared" if detection is inconclusive.
detect_cloudflared_user() {
  local candidate

  # Prefer an explicit match: any home directory with the Quadlet container
  # file this setup writes.
  for pw_home in $(getent passwd | awk -F: '{print $6}'); do
    if [[ -f "${pw_home}/.config/containers/systemd/cloudflared.container" ]]; then
      candidate="$(getent passwd | awk -F: -v h="$pw_home" '$6==h {print $1; exit}')"
      if [[ -n "$candidate" ]]; then
        echo "$candidate"
        return 0
      fi
    fi
  done

  # Fall back to the conventional default username.
  if user_exists "cloudflared"; then
    echo "cloudflared"
    return 0
  fi

  return 1
}

resolve_cf_user() {
  local detected=""
  detected="$(detect_cloudflared_user || true)"

  if [[ -n "$detected" ]]; then
    read -r -p "Username running cloudflared [${detected}]: " CF_USER
    CF_USER="${CF_USER:-$detected}"
  else
    read -r -p "Username running cloudflared: " CF_USER
    [[ -n "$CF_USER" ]] || die "Username cannot be empty"
  fi

  user_exists "$CF_USER" || die "User '${CF_USER}' does not exist on this system"

  QUADLET_DIR="$(user_home "$CF_USER")/.config/containers/systemd"
  DROPIN_DIR="${QUADLET_DIR}/cloudflared.container.d"
  IMAGE_DROPIN="${DROPIN_DIR}/40-image.conf"

  [[ -d "$QUADLET_DIR" ]] || die "Quadlet directory not found for ${CF_USER}: ${QUADLET_DIR}"
}

#------------------------------------------------------------------------------
# 1) Show cloudflared container status
#------------------------------------------------------------------------------
action_status() {
  echo
  info "== podman status (as user: ${CF_USER}) =="
  user_run "$CF_USER" "podman ps -a --filter name=cloudflared" || warn "Failed to list podman containers"

  echo
  user_run "$CF_USER" "podman inspect cloudflared --format 'State: {{.State.Status}}  |  Started: {{.State.StartedAt}}  |  Image: {{.Config.Image}}'" 2>/dev/null || \
    warn "Could not inspect 'cloudflared' container (it may not be running)"

  echo
  info "== systemctl --user status cloudflared.container (as user: ${CF_USER}) =="
  user_systemctl "$CF_USER" status cloudflared.container -l --no-pager || \
    warn "Could not read systemctl --user status for cloudflared.container"

  echo
  info "== Recent journal (last 30 lines) =="
  if user_systemctl "$CF_USER" list-units cloudflared.service >/dev/null 2>&1; then
    sudo -u "$CF_USER" env XDG_RUNTIME_DIR="/run/user/$(user_uid "$CF_USER")" \
      journalctl --user -u cloudflared.service -n 30 --no-pager 2>/dev/null || \
      warn "Could not read recent journal entries"
  else
    warn "cloudflared.service unit not found; skipping journal output"
  fi
}

#------------------------------------------------------------------------------
# 2) Restart the cloudflared container
#------------------------------------------------------------------------------
action_restart() {
  echo
  info "Restarting cloudflared.service for user: ${CF_USER}"
  user_systemctl "$CF_USER" restart cloudflared.service || die "Failed to restart cloudflared.service"

  sleep 2
  info "Restart complete. Current status:"
  user_systemctl "$CF_USER" status cloudflared.service -l --no-pager || true
}

#------------------------------------------------------------------------------
# 3) Upgrade the cloudflared container
#------------------------------------------------------------------------------
action_upgrade() {
  [[ -f "$IMAGE_DROPIN" ]] || die "Image drop-in not found: ${IMAGE_DROPIN}"

  local current_tag=""
  current_tag="$(grep -E '^Image=' "$IMAGE_DROPIN" 2>/dev/null | sed -E 's#^Image=docker\.io/cloudflare/cloudflared:##')"

  echo
  info "Current image tag: ${current_tag:-unknown}"
  read -r -p "Enter the new cloudflared image tag (e.g., 2025.11.1): " NEW_TAG
  [[ -n "$NEW_TAG" ]] || die "Image tag cannot be empty"

  if [[ "$NEW_TAG" == "$current_tag" ]]; then
    read -r -p "New tag matches the current tag (${current_tag}). Continue anyway? [y/N]: " confirm_same
    [[ "${confirm_same,,}" == "y" ]] || { info "Upgrade cancelled."; return 0; }
  fi

  local new_image="docker.io/cloudflare/cloudflared:${NEW_TAG}"

  info "Pulling new image as user ${CF_USER}: ${new_image}"
  user_run "$CF_USER" "podman pull '${new_image}'" || die "Failed to pull image: ${new_image}"

  info "Updating image drop-in: ${IMAGE_DROPIN}"
  cat >"${IMAGE_DROPIN}" <<EOF
[Container]
Image=${new_image}
Pull=never
EOF
  chown "${CF_USER}:${CF_USER}" "${IMAGE_DROPIN}"
  chmod 0600 "${IMAGE_DROPIN}"

  info "Reloading systemd --user daemon for user: ${CF_USER}"
  user_systemctl "$CF_USER" daemon-reload || die "Failed to reload user daemon"

  echo
  read -r -p "Restart cloudflared.service now to apply the new image? [Y/n]: " do_restart
  do_restart="${do_restart:-y}"
  if [[ "${do_restart,,}" == "y" ]]; then
    user_systemctl "$CF_USER" restart cloudflared.service || die "Failed to restart cloudflared.service after upgrade"
    sleep 2
    info "Upgrade complete. Current status:"
    user_systemctl "$CF_USER" status cloudflared.service -l --no-pager || true
  else
    warn "Image updated but service not restarted. The old container keeps running the previous image until restarted."
  fi
}

print_menu() {
  echo
  echo "=========================================="
  echo " cloudflared-container management (user: ${CF_USER})"
  echo "=========================================="
  echo "  1) Show status"
  echo "  2) Restart container"
  echo "  3) Upgrade container (change image tag)"
  echo "  4) Switch user"
  echo "  q) Quit"
  echo
}

main() {
  require_root
  resolve_cf_user

  # Allow non-interactive one-shot invocation: cloudflared-container status|restart|upgrade
  if [[ "${1:-}" != "" ]]; then
    case "${1}" in
      status)  action_status ;;
      restart) action_restart ;;
      upgrade) action_upgrade ;;
      *) die "Unknown action: ${1}. Valid actions: status, restart, upgrade" ;;
    esac
    exit 0
  fi

  while true; do
    print_menu
    read -r -p "Select an option: " choice
    case "$choice" in
      1) action_status ;;
      2) action_restart ;;
      3) action_upgrade ;;
      4) resolve_cf_user ;;
      q|Q) info "Exiting."; exit 0 ;;
      *) warn "Invalid selection: ${choice}" ;;
    esac
  done
}

main "$@"
MANAGE_SCRIPT_EOF

  chmod 0755 "${install_path}"
  chown root:root "${install_path}"

  info "Management command installed: ${install_path}"
  info "  Run interactively: sudo cloudflared-container"
  info "  Or non-interactively: sudo cloudflared-container status|restart|upgrade"
}

create_quadlet_rootless() {
  local u="$1" tag="$2" token="$3"
  local homedir quadlet_dir container_file dropin_dir image_dropin icmp_dropin token_dropin env_file

  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || die "Could not determine home directory for user: $u"

  quadlet_dir="${homedir}/.config/containers/systemd"
  container_file="${quadlet_dir}/cloudflared.container"
  dropin_dir="${quadlet_dir}/cloudflared.container.d"
  image_dropin="${dropin_dir}/40-image.conf"
  icmp_dropin="${dropin_dir}/50-icmp.conf"
  token_dropin="${dropin_dir}/50-token.conf"
  env_file="${dropin_dir}/cloudflared.env"

  info "Creating Quadlet files for user $u"

  install -d -m 0700 -o "$u" -g "$u" "$quadlet_dir"
  install -d -m 0700 -o "$u" -g "$u" "$dropin_dir"

  cat >"$container_file" <<'EOF'
[Unit]
Description=CloudflareD Tunnel Agent (cloudflared) Container
Wants=network-online.target
After=network-online.target

[Container]
ContainerName=cloudflared
Exec=tunnel --no-autoupdate run

[Service]
Restart=always
TimeoutStartSec=900

[Install]
WantedBy=default.target
EOF
  chown "$u:$u" "$container_file"
  chmod 0600 "$container_file"

  cat >"$image_dropin" <<EOF
[Container]
Image=docker.io/cloudflare/cloudflared:${tag}
Pull=never
EOF
  chown "$u:$u" "$image_dropin"
  chmod 0600 "$image_dropin"

  cat >"$icmp_dropin" <<EOF
[Container]
Sysctl="net.ipv4.ping_group_range=65532 65532"
EOF
  chown "$u:$u" "$icmp_dropin"
  chmod 0600 "$icmp_dropin"

  # Pass the tunnel token via environment rather than as a CLI argument.
  # A --token CLI arg would be visible to any local user via `ps` or
  # /proc/<pid>/cmdline (both world-readable), regardless of file
  # permissions on this drop-in. Env vars land in /proc/<pid>/environ,
  # which is readable only by the owning user and root.
  cat >"$env_file" <<EOF
TUNNEL_TOKEN=${token}
EOF
  chown "$u:$u" "$env_file"
  chmod 0600 "$env_file"

  cat >"$token_dropin" <<EOF
[Container]
EnvironmentFile=${env_file}

[Service]
LimitNOFILE=250000
EOF
  chown "$u:$u" "$token_dropin"
  chmod 0600 "$token_dropin"

  info "Reloading generator and starting service as user $u"
  user_systemctl "$u" daemon-reload
  user_systemctl "$u" reset-failed cloudflared.service || true
  user_systemctl "$u" start cloudflared.service
  user_systemctl "$u" status cloudflared.service -l --no-pager || true
}

main() {
  require_root

  iface_exists eth0 || die "Interface eth0 not found. This script expects eth0 as the primary NIC."

  install_packages

  echo
  read -r -p "Enter username to run cloudflared (rootless) [cloudflared]: " CF_USER
  CF_USER="${CF_USER:-cloudflared}"
  ensure_user "${CF_USER}"

  read -r -p "Enter cloudflared image tag (e.g., 2025.11.1): " CF_TAG
  [[ -n "${CF_TAG}" ]] || die "Image tag cannot be empty"

  echo
  read -r -s -p "Enter Cloudflare tunnel token (dashboard-generated): " CF_TOKEN
  echo
  [[ -n "${CF_TOKEN}" ]] || die "Tunnel token cannot be empty"

  echo
  read -r -p "Does this server have 1 or 2 network interfaces for routing? [1/2]: " NIC_COUNT
  [[ "${NIC_COUNT}" == "1" || "${NIC_COUNT}" == "2" ]] || die "Enter 1 or 2"

  APPLY_POLICY_ROUTING="n"
  ETH1_IP=""

  if [[ "${NIC_COUNT}" == "2" ]]; then
    iface_exists eth1 || die "You selected 2 NICs, but interface eth1 was not found."

    echo
    read -r -p "Configure origin policy routing for cloudflared using eth1? [y/N]: " APPLY_POLICY_ROUTING
    APPLY_POLICY_ROUTING="${APPLY_POLICY_ROUTING:-n}"

    if [[ "${APPLY_POLICY_ROUTING}" =~ ^[Yy]$ ]]; then
      ETH1_IP="$(get_ipv4_addr_for_dev eth1 || true)"
      [[ -n "${ETH1_IP}" ]] || die "Could not determine IPv4 address for eth1. Configure eth1 with an IPv4 address before enabling origin policy routing."
      info "Detected eth1 IPv4 address: ${ETH1_IP}"
    else
      info "Skipping origin policy routing as requested."
    fi
  else
    info "Single-NIC selected; skipping origin route-table configuration."
  fi

  enable_persistent_journaling
  enable_linger_for_user "${CF_USER}"
  write_sysctl_cloudflared

  if [[ "${NIC_COUNT}" == "2" && "${APPLY_POLICY_ROUTING}" =~ ^[Yy]$ ]]; then
    configure_policy_routing_two_nic "${ETH1_IP}"
  fi

  pull_cloudflared_image_rootless "${CF_USER}" "${CF_TAG}"
  create_quadlet_rootless "${CF_USER}" "${CF_TAG}" "${CF_TOKEN}"

  install_management_command

  info "Installing cloudflared aliases for user ${CF_USER}"

  cat >/etc/profile.d/cloudflared-aliases.sh <<EOF
alias cloudflared-status='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user status cloudflared.service'
alias cloudflared-stop='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user stop cloudflared.service'
alias cloudflared-start='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user start cloudflared.service'
alias cloudflared-restart='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user restart cloudflared.service'
EOF

  chmod 0644 /etc/profile.d/cloudflared-aliases.sh

  info "Done. Verify after reboot:"
  echo "  sudo -u ${CF_USER} env XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user status cloudflared.service -l --no-pager"
  echo "  journalctl --user -u cloudflared.service -b --no-pager | tail -n 200"
  if [[ "${NIC_COUNT}" == "2" && "${APPLY_POLICY_ROUTING}" =~ ^[Yy]$ ]]; then
    echo "  ip rule show"
    echo "  ip route show table origin"
  fi
}

main "$@"
