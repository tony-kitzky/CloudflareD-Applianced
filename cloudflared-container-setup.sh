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
#  2) Prompt for the "prod" instance:
#      a) username to run rootless cloudflared (create if missing) -- default: cloudflared
#      b) cloudflared image tag
#      c) cloudflared tunnel token (dashboard-generated)
#  3) OPTIONAL: prompt to also install a second "dev" instance, with its own:
#      a) username (may reuse the prod user or be a distinct account)
#      b) cloudflared image tag
#      c) cloudflared tunnel token
#  4) Enable persistent journaling + per-user journals
#  5) Enable boot-start for user services (linger) for each instance's user
#  6) Write /etc/sysctl.d/99-cloudflared.conf to update system limits for ping users and udp socket buffers
#  7) Pull cloudflared image (fully-qualified docker.io/cloudflare/cloudflared:<tag>) per instance
#  8) Create Quadlet base + drop-ins per instance:
#      - prod unit: cloudflared.service (container file: cloudflared.container)
#      - dev unit:  cloudflared-dev.service (container file: cloudflared-dev.container)
#      - dev drop-in files are suffixed "-dev" to keep them unambiguous
#  9) Start each instance's systemd --user service
# 10) Install a dedicated /usr/local/sbin/cloudflared-container-<instance>
#     management command per instance (menu-driven status/restart/upgrade
#     tool; usable by any sudoer)
# 11) Write /etc/profile.d/cloudflare-alias.sh (aliases for both instances,
#     if dev was installed)
#
# Notes:
#  - Token is stored on disk in a drop-in file (0600). Protect the user account.
#  - Rootless systemd user services require a working user runtime dir; the script
#    sets XDG_RUNTIME_DIR to avoid "Failed to connect to bus: No medium found".
#  - The "prod" and "dev" instances are independent Quadlet units and may run
#    under the same rootless user or two different rootless users.
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
net.core.rmem_max = 12000000
net.core.wmem_max = 12000000
EOF

  sysctl --system >/dev/null
}

pull_cloudflared_image_rootless() {
  local u="$1" tag="$2"
  local homedir
  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || die "Could not determine home directory for user: $u"

  info "Pulling image as rootless user $u: docker.io/cloudflare/cloudflared:${tag}"
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman pull 'docker.io/cloudflare/cloudflared:${tag}'"
}

# Install a dedicated management command for one cloudflared instance.
#   instance: "prod" or "dev"
#   default_user: the rootless user this instance was just provisioned under,
#                 used only as the initial suggested default in the prompt --
#                 the installed command still supports switching users.
# Installs to: /usr/local/sbin/cloudflared-container-<instance>
install_management_command() {
  local instance="$1" default_user="$2"
  local install_path="/usr/local/sbin/cloudflared-container-${instance}"
  local unit_base container_name

  if [[ "$instance" == "prod" ]]; then
    unit_base="cloudflared"
    container_name="cloudflared"
  else
    unit_base="cloudflared-dev"
    container_name="cloudflared-dev"
  fi

  info "Installing cloudflared-container-${instance} management command to: ${install_path}"

  cat >"${install_path}" <<'MANAGE_SCRIPT_EOF'
#!/usr/bin/env bash
#------------------------------------------------------------------------------
# cloudflared-container-__INSTANCE__
# Menu-driven management tool for the rootless "__CONTAINER_NAME__"
# Podman Quadlet deployment created by cloudflared-container-setup.sh.
#
# Manages the __UNIT_BASE__.service unit (instance: __INSTANCE__) only.
#
# Must be run with sudo/root. Internally switches to the cloudflared user's
# systemd --user session via XDG_RUNTIME_DIR so any sudoer can manage the
# container without needing to log in as that user directly.
#
# Usage:
#   sudo cloudflared-container-__INSTANCE__
#------------------------------------------------------------------------------

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*" >&2; }
warn() { echo "WARN: $*" >&2; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo cloudflared-container-__INSTANCE__"; }

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

# Try to auto-detect the user running this instance's cloudflared Quadlet
# service by scanning for anyone with the instance's Quadlet container file.
# Falls back to "cloudflared" if detection is inconclusive.
detect_cloudflared_user() {
  local candidate

  # Prefer an explicit match: any home directory with this instance's
  # Quadlet container file.
  for pw_home in $(getent passwd | awk -F: '{print $6}'); do
    if [[ -f "${pw_home}/.config/containers/systemd/__UNIT_BASE__.container" ]]; then
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
    read -r -p "Username running __INSTANCE__ cloudflared [${detected}]: " CF_USER
    CF_USER="${CF_USER:-$detected}"
  else
    read -r -p "Username running __INSTANCE__ cloudflared: " CF_USER
    [[ -n "$CF_USER" ]] || die "Username cannot be empty"
  fi

  user_exists "$CF_USER" || die "User '${CF_USER}' does not exist on this system"

  QUADLET_DIR="$(user_home "$CF_USER")/.config/containers/systemd"
  DROPIN_DIR="${QUADLET_DIR}/__UNIT_BASE__.container.d"
  IMAGE_DROPIN="${DROPIN_DIR}/__IMAGE_DROPIN_NAME__"
  TOKEN_ENV_FILE="${DROPIN_DIR}/__TOKEN_ENV_NAME__"

  [[ -d "$QUADLET_DIR" ]] || die "Quadlet directory not found for ${CF_USER}: ${QUADLET_DIR}"
}

#------------------------------------------------------------------------------
# 1) Show cloudflared container status (instance: __INSTANCE__)
#------------------------------------------------------------------------------
action_status() {
  echo
  info "== podman status (as user: ${CF_USER}) =="
  user_run "$CF_USER" "podman ps -a --filter name=__CONTAINER_NAME__" || warn "Failed to list podman containers"

  echo
  user_run "$CF_USER" "podman inspect __CONTAINER_NAME__ --format 'State: {{.State.Status}}  |  Started: {{.State.StartedAt}}  |  Image: {{.Config.Image}}'" 2>/dev/null || \
    warn "Could not inspect '__CONTAINER_NAME__' container (it may not be running)"

  echo
  info "== systemctl --user status __UNIT_BASE__.container (as user: ${CF_USER}) =="
  user_systemctl "$CF_USER" status __UNIT_BASE__.container -l --no-pager || \
    warn "Could not read systemctl --user status for __UNIT_BASE__.container"

  echo
  info "== Recent journal (last 30 lines) =="
  if user_systemctl "$CF_USER" list-units __UNIT_BASE__.service >/dev/null 2>&1; then
    sudo -u "$CF_USER" env XDG_RUNTIME_DIR="/run/user/$(user_uid "$CF_USER")" \
      journalctl --user -u __UNIT_BASE__.service -n 30 --no-pager 2>/dev/null || \
      warn "Could not read recent journal entries"
  else
    warn "__UNIT_BASE__.service unit not found; skipping journal output"
  fi
}

#------------------------------------------------------------------------------
# 2) Restart the cloudflared container (instance: __INSTANCE__)
#------------------------------------------------------------------------------
action_restart() {
  echo
  info "Restarting __UNIT_BASE__.service for user: ${CF_USER}"
  user_systemctl "$CF_USER" restart __UNIT_BASE__.service || die "Failed to restart __UNIT_BASE__.service"

  sleep 2
  info "Restart complete. Current status:"
  user_systemctl "$CF_USER" status __UNIT_BASE__.service -l --no-pager || true
}

#------------------------------------------------------------------------------
# 3) Stop the cloudflared container (instance: __INSTANCE__)
#------------------------------------------------------------------------------
action_stop() {
  echo
  info "Stopping __UNIT_BASE__.service for user: ${CF_USER}"
  user_systemctl "$CF_USER" stop __UNIT_BASE__.service || die "Failed to stop __UNIT_BASE__.service"

  sleep 1
  info "Stop complete. Current status:"
  user_systemctl "$CF_USER" status __UNIT_BASE__.service -l --no-pager || true
}

#------------------------------------------------------------------------------
# 4) Start the cloudflared container (instance: __INSTANCE__)
#------------------------------------------------------------------------------
action_start() {
  echo
  info "Starting __UNIT_BASE__.service for user: ${CF_USER}"
  user_systemctl "$CF_USER" start __UNIT_BASE__.service || die "Failed to start __UNIT_BASE__.service"

  sleep 2
  info "Start complete. Current status:"
  user_systemctl "$CF_USER" status __UNIT_BASE__.service -l --no-pager || true
}

#------------------------------------------------------------------------------
# 5) Upgrade the cloudflared container
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
  read -r -p "Restart __UNIT_BASE__.service now to apply the new image? [Y/n]: " do_restart
  do_restart="${do_restart:-y}"
  if [[ "${do_restart,,}" == "y" ]]; then
    user_systemctl "$CF_USER" restart __UNIT_BASE__.service || die "Failed to restart __UNIT_BASE__.service after upgrade"
    sleep 2
    info "Upgrade complete. Current status:"
    user_systemctl "$CF_USER" status __UNIT_BASE__.service -l --no-pager || true
  else
    warn "Image updated but service not restarted. The old container keeps running the previous image until restarted."
  fi
}

#------------------------------------------------------------------------------
# 6) Change the tunnel token (instance: __INSTANCE__)
#------------------------------------------------------------------------------
action_change_token() {
  [[ -f "$TOKEN_ENV_FILE" ]] || die "Token env file not found: ${TOKEN_ENV_FILE}"

  echo
  warn "The new token will be visible on screen while typing."
  read -r -p "Enter the new tunnel token: " NEW_TOKEN
  [[ -n "$NEW_TOKEN" ]] || die "Token cannot be empty"

  info "Updating token file: ${TOKEN_ENV_FILE}"
  cat >"${TOKEN_ENV_FILE}" <<EOF
TUNNEL_TOKEN=${NEW_TOKEN}
EOF
  chown "${CF_USER}:${CF_USER}" "${TOKEN_ENV_FILE}"
  chmod 0600 "${TOKEN_ENV_FILE}"

  info "Reloading systemd --user daemon for user: ${CF_USER}"
  user_systemctl "$CF_USER" daemon-reload || die "Failed to reload user daemon"

  echo
  read -r -p "Restart __UNIT_BASE__.service now to apply the new token? [Y/n]: " do_restart
  do_restart="${do_restart:-y}"
  if [[ "${do_restart,,}" == "y" ]]; then
    user_systemctl "$CF_USER" restart __UNIT_BASE__.service || die "Failed to restart __UNIT_BASE__.service after token change"
    sleep 2
    info "Token updated. Current status:"
    user_systemctl "$CF_USER" status __UNIT_BASE__.service -l --no-pager || true
  else
    warn "Token updated but service not restarted. The old token stays active until restarted."
  fi
}

#------------------------------------------------------------------------------
# 7) Reload the systemd --user daemon
#------------------------------------------------------------------------------
action_daemon_reload() {
  echo
  info "Running systemctl --user daemon-reload for user: ${CF_USER}"
  user_systemctl "$CF_USER" daemon-reload || die "Failed to reload user daemon"
  info "Daemon reload complete."
}

print_menu() {
  echo
  echo "=========================================="
  echo " cloudflared-container-__INSTANCE__ management (user: ${CF_USER})"
  echo "=========================================="
  echo "  1) Show status"
  echo "  2) Restart container"
  echo "  3) Stop container"
  echo "  4) Start container"
  echo "  5) Upgrade container (change image tag)"
  echo "  6) Change tunnel token"
  echo "  7) Reload systemd --user daemon"
  echo "  8) Switch to different container user"
  echo "  q) Quit"
  echo
}

main() {
  require_root
  resolve_cf_user

  # Allow non-interactive one-shot invocation:
  #   cloudflared-container-__INSTANCE__ status|restart|stop|start|upgrade|change-token|daemon-reload
  if [[ "${1:-}" != "" ]]; then
    case "${1}" in
      status)        action_status ;;
      restart)       action_restart ;;
      stop)          action_stop ;;
      start)         action_start ;;
      upgrade)       action_upgrade ;;
      change-token)  action_change_token ;;
      daemon-reload) action_daemon_reload ;;
      *) die "Unknown action: ${1}. Valid actions: status, restart, stop, start, upgrade, change-token, daemon-reload" ;;
    esac
    exit 0
  fi

  while true; do
    print_menu
    read -r -p "Select an option: " choice
    case "$choice" in
      1) action_status ;;
      2) action_restart ;;
      3) action_stop ;;
      4) action_start ;;
      5) action_upgrade ;;
      6) action_change_token ;;
      7) action_daemon_reload ;;
      8) resolve_cf_user ;;
      q|Q) info "Exiting."; exit 0 ;;
      *) warn "Invalid selection: ${choice}" ;;
    esac
  done
}

main "$@"
MANAGE_SCRIPT_EOF

  # Bake this instance's fixed identifiers into the otherwise-generic
  # embedded script. The heredoc above is single-quoted (no shell
  # expansion at write time) so the __TOKEN__ placeholders land in the
  # file literally; substitute them now for this specific instance.
  local image_dropin_name token_env_name
  if [[ "$instance" == "prod" ]]; then
    image_dropin_name="40-image.conf"
    token_env_name="cloudflared.env"
  else
    image_dropin_name="40-image-dev.conf"
    token_env_name="cloudflared-dev.env"
  fi

  sed -i \
    -e "s/__INSTANCE__/${instance}/g" \
    -e "s/__UNIT_BASE__/${unit_base}/g" \
    -e "s/__CONTAINER_NAME__/${container_name}/g" \
    -e "s/__IMAGE_DROPIN_NAME__/${image_dropin_name}/g" \
    -e "s/__TOKEN_ENV_NAME__/${token_env_name}/g" \
    "${install_path}"

  chmod 0755 "${install_path}"
  chown root:root "${install_path}"

  info "Management command installed: ${install_path}"
  info "  Run interactively: sudo cloudflared-container-${instance}"
  info "  Or non-interactively: sudo cloudflared-container-${instance} status|restart|upgrade"
  # default_user is accepted for symmetry/future use (e.g. pre-seeding a
  # config file); resolve_cf_user() re-detects the user at runtime instead.
  : "${default_user}"
}

# Create the Quadlet unit + drop-ins for one cloudflared instance.
#   instance: "prod" or "dev"
#     - prod uses unit basename "cloudflared" (unit: cloudflared.service)
#     - dev uses unit basename "cloudflared-dev" (unit: cloudflared-dev.service)
#       and all drop-in filenames are suffixed "-dev"
create_quadlet_rootless() {
  local instance="$1" u="$2" tag="$3" token="$4"
  local homedir quadlet_dir unit_base container_name container_file dropin_dir
  local image_dropin icmp_dropin token_dropin env_file suffix

  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || die "Could not determine home directory for user: $u"

  if [[ "$instance" == "prod" ]]; then
    unit_base="cloudflared"
    container_name="cloudflared"
    suffix=""
  else
    unit_base="cloudflared-dev"
    container_name="cloudflared-dev"
    suffix="-dev"
  fi

  quadlet_dir="${homedir}/.config/containers/systemd"
  container_file="${quadlet_dir}/${unit_base}.container"
  dropin_dir="${quadlet_dir}/${unit_base}.container.d"
  image_dropin="${dropin_dir}/40-image${suffix}.conf"
  icmp_dropin="${dropin_dir}/50-icmp${suffix}.conf"
  token_dropin="${dropin_dir}/50-token${suffix}.conf"
  env_file="${dropin_dir}/cloudflared${suffix}.env"

  info "Creating Quadlet files for instance '${instance}' (unit: ${unit_base}.service) under user $u"

  install -d -m 0700 -o "$u" -g "$u" "$quadlet_dir"
  install -d -m 0700 -o "$u" -g "$u" "$dropin_dir"

  cat >"$container_file" <<EOF
[Unit]
Description=CloudflareD Tunnel Agent (cloudflared) Container -- ${instance}
Wants=network-online.target
After=network-online.target

[Container]
ContainerName=${container_name}
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
  user_systemctl "$u" reset-failed "${unit_base}.service" || true
  user_systemctl "$u" start "${unit_base}.service"
  user_systemctl "$u" status "${unit_base}.service" -l --no-pager || true
}

# Append profile.d alias definitions for one instance to the shared
# aliases file. unit_base/alias_suffix let prod keep unsuffixed alias
# names (cloudflared-status) while dev gets "-dev" suffixed names
# (cloudflared-status-dev), avoiding collisions when both are installed.
write_cloudflared_aliases() {
  local instance_user="$1" unit_base="$2" alias_suffix="$3"

  cat >>/etc/profile.d/cloudflared-aliases.sh <<EOF
alias cloudflared-status${alias_suffix}='sudo -u ${instance_user} XDG_RUNTIME_DIR=/run/user/\$(id -u ${instance_user}) systemctl --user status ${unit_base}.service'
alias cloudflared-stop${alias_suffix}='sudo -u ${instance_user} XDG_RUNTIME_DIR=/run/user/\$(id -u ${instance_user}) systemctl --user stop ${unit_base}.service'
alias cloudflared-start${alias_suffix}='sudo -u ${instance_user} XDG_RUNTIME_DIR=/run/user/\$(id -u ${instance_user}) systemctl --user start ${unit_base}.service'
alias cloudflared-restart${alias_suffix}='sudo -u ${instance_user} XDG_RUNTIME_DIR=/run/user/\$(id -u ${instance_user}) systemctl --user restart ${unit_base}.service'
EOF
}

main() {
  require_root

  iface_exists eth0 || die "Interface eth0 not found. This script expects eth0 as the primary NIC."

  install_packages

  #-----------------------------------------------------------------------
  # "prod" instance (always installed)
  #-----------------------------------------------------------------------
  echo
  info "Configuring the 'prod' cloudflared container"
  read -r -p "Enter username to run prod cloudflared (rootless) [cloudflared]: " CF_USER
  CF_USER="${CF_USER:-cloudflared}"
  ensure_user "${CF_USER}"

  read -r -p "Enter prod cloudflared image tag (e.g., 2025.11.1): " CF_TAG
  [[ -n "${CF_TAG}" ]] || die "Image tag cannot be empty"

  echo
  read -r -s -p "Enter prod Cloudflare tunnel token (dashboard-generated): " CF_TOKEN
  echo
  [[ -n "${CF_TOKEN}" ]] || die "Tunnel token cannot be empty"

  enable_persistent_journaling
  write_sysctl_cloudflared

  enable_linger_for_user "${CF_USER}"
  pull_cloudflared_image_rootless "${CF_USER}" "${CF_TAG}"
  create_quadlet_rootless "prod" "${CF_USER}" "${CF_TAG}" "${CF_TOKEN}"
  install_management_command "prod" "${CF_USER}"

  #-----------------------------------------------------------------------
  # "dev" instance (optional)
  #-----------------------------------------------------------------------
  echo
  read -r -p "Install a second (dev) cloudflared container? [y/N]: " INSTALL_DEV
  INSTALL_DEV="${INSTALL_DEV:-n}"

  local DEV_USER=""
  if [[ "${INSTALL_DEV,,}" == "y" ]]; then
    info "Configuring the 'dev' cloudflared container"

    read -r -p "Does the dev container need a second (different) userid than '${CF_USER}'? [y/N]: " NEED_SECOND_USER
    NEED_SECOND_USER="${NEED_SECOND_USER:-n}"

    if [[ "${NEED_SECOND_USER,,}" == "y" ]]; then
      read -r -p "Enter username to run dev cloudflared (rootless) [cloudflared-dev]: " DEV_USER
      DEV_USER="${DEV_USER:-cloudflared-dev}"
      ensure_user "${DEV_USER}"
    else
      DEV_USER="${CF_USER}"
      info "Dev container will run under the same user as prod: ${DEV_USER}"
    fi

    read -r -p "Enter dev cloudflared image tag (e.g., 2025.11.1): " DEV_TAG
    [[ -n "${DEV_TAG}" ]] || die "Image tag cannot be empty"

    echo
    read -r -s -p "Enter dev Cloudflare tunnel token (dashboard-generated): " DEV_TOKEN
    echo
    [[ -n "${DEV_TOKEN}" ]] || die "Tunnel token cannot be empty"

    enable_linger_for_user "${DEV_USER}"
    pull_cloudflared_image_rootless "${DEV_USER}" "${DEV_TAG}"
    create_quadlet_rootless "dev" "${DEV_USER}" "${DEV_TAG}" "${DEV_TOKEN}"
    install_management_command "dev" "${DEV_USER}"
  else
    info "Skipping dev container installation."
  fi

  #-----------------------------------------------------------------------
  # Shared profile.d aliases
  #-----------------------------------------------------------------------
  info "Installing cloudflared aliases for user ${CF_USER}"
  : >/etc/profile.d/cloudflared-aliases.sh
  write_cloudflared_aliases "${CF_USER}" "cloudflared" ""

  if [[ "${INSTALL_DEV,,}" == "y" ]]; then
    info "Installing dev cloudflared aliases for user ${DEV_USER}"
    write_cloudflared_aliases "${DEV_USER}" "cloudflared-dev" "-dev"
  fi

  chmod 0644 /etc/profile.d/cloudflared-aliases.sh

  info "Done. Verify after reboot:"
  echo "  sudo -u ${CF_USER} env XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user status cloudflared.service -l --no-pager"
  echo "  journalctl --user -u cloudflared.service -b --no-pager | tail -n 200"
  echo "  Manage prod: sudo cloudflared-container-prod"

  if [[ "${INSTALL_DEV,,}" == "y" ]]; then
    echo "  sudo -u ${DEV_USER} env XDG_RUNTIME_DIR=/run/user/\$(id -u ${DEV_USER}) systemctl --user status cloudflared-dev.service -l --no-pager"
    echo "  journalctl --user -u cloudflared-dev.service -b --no-pager | tail -n 200"
    echo "  Manage dev: sudo cloudflared-container-dev"
  fi
}

main "$@"
