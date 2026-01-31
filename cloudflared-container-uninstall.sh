#!/usr/bin/env bash
#------------------------------------------------------------------------------
# cloudflared-container-uninstall.sh
# Uninstall the cloudflared rootless container setup on Alma Linux 9 server
#
# This script reverses the changes made by cloudflared-container-setup.sh:
#  1) Stop and disable the cloudflared service
#  2) Remove Quadlet configuration files
#  3) Remove the cloudflared container and image
#  4) Disable user linger
#  5) Remove sysctl configuration
#  6) Remove RFC1918 static routes (if 2 NIC setup was used)
#  7) Remove persistent journaling configuration
#  8) Optionally remove the cloudflared user account
#
# Usage:
#   sudo bash cloudflared-container-uninstall.sh
#------------------------------------------------------------------------------

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*" >&2; }
warn() { echo "WARN: $*" >&2; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"; }

user_exists() { id "$1" >/dev/null 2>&1; }

user_uid() { id -u "$1"; }

is_systemctl_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# Run systemctl --user for a given user
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

# Check if service exists for user
user_service_exists() {
  local u="$1" service="$2"
  local uid; uid="$(user_uid "$u")"
  local runtime_dir="/run/user/${uid}"

  sudo -u "$u" env XDG_RUNTIME_DIR="$runtime_dir" \
    systemctl --user list-unit-files "$service" 2>/dev/null | grep -q "$service" || return 1
}

stop_and_disable_service() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping service stop"
    return 0
  fi

  info "Stopping and disabling cloudflared service for user: $u"
  
  if user_service_exists "$u" cloudflared.service; then
    user_systemctl "$u" stop cloudflared.service 2>/dev/null || warn "Failed to stop cloudflared.service"
    user_systemctl "$u" disable cloudflared.service 2>/dev/null || warn "Failed to disable cloudflared.service"
  else
    warn "cloudflared.service not found for user $u"
  fi
}

remove_container_and_image() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping container removal"
    return 0
  fi

  local homedir
  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || { warn "Could not determine home directory for user: $u"; return 0; }

  info "Removing cloudflared container and images for user: $u"
  
  # Remove container
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman rm -f cloudflared 2>/dev/null || true"
  
  # Remove all cloudflared images
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman rmi -f \$(podman images 'docker.io/cloudflare/cloudflared' -q) 2>/dev/null || true"
  
  info "Container and images removed"
}

remove_quadlet_files() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping Quadlet file removal"
    return 0
  fi

  local homedir quadlet_dir
  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || { warn "Could not determine home directory for user: $u"; return 0; }

  quadlet_dir="${homedir}/.config/containers/systemd"

  if [[ -d "$quadlet_dir" ]]; then
    info "Removing Quadlet configuration files from: $quadlet_dir"
    rm -rf "${quadlet_dir}/cloudflared.container" \
           "${quadlet_dir}/cloudflared.container.d" 2>/dev/null || true
    
    # Reload daemon to remove generated service files
    user_systemctl "$u" daemon-reload 2>/dev/null || warn "Failed to reload user daemon"
  else
    warn "Quadlet directory not found: $quadlet_dir"
  fi
}

disable_linger() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping linger disable"
    return 0
  fi

  info "Disabling linger for user: $u"
  loginctl disable-linger "$u" 2>/dev/null || warn "Failed to disable linger for $u"
}

remove_sysctl_config() {
  local sysctl_file="/etc/sysctl.d/99-cloudflared.conf"
  
  if [[ -f "$sysctl_file" ]]; then
    info "Removing sysctl configuration: $sysctl_file"
    rm -f "$sysctl_file"
    sysctl --system >/dev/null 2>&1 || warn "Failed to reload sysctl settings"
  else
    warn "sysctl configuration not found: $sysctl_file"
  fi
}

remove_rfc1918_routes() {
  info "Removing RFC1918 static routes from eth1 (if configured)"

  # Remove runtime routes (ignore errors if they don't exist)
  ip route del 10.0.0.0/8 dev eth1 2>/dev/null || true
  ip route del 172.16.0.0/12 dev eth1 2>/dev/null || true
  ip route del 192.168.0.0/16 dev eth1 2>/dev/null || true

  # Remove from NetworkManager if active
  if is_systemctl_active NetworkManager.service && command -v nmcli >/dev/null 2>&1; then
    info "Removing RFC1918 routes from NetworkManager eth1 connection profile"

    local con1
    con1="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: '$2=="eth1" {print $1; exit}')"
    
    if [[ -n "$con1" ]]; then
      # Remove the static routes
      nmcli con mod "$con1" -ipv4.routes "10.0.0.0/8" 2>/dev/null || true
      nmcli con mod "$con1" -ipv4.routes "172.16.0.0/12" 2>/dev/null || true
      nmcli con mod "$con1" -ipv4.routes "192.168.0.0/16" 2>/dev/null || true
      
      # Re-enable default route on eth1 (remove never-default flag)
      nmcli con mod "$con1" ipv4.never-default no 2>/dev/null || true
      
      nmcli con up "$con1" >/dev/null 2>&1 || warn "Failed to bring up connection: $con1"
      
      info "RFC1918 routes removed from NetworkManager"
    else
      warn "No active NetworkManager connection found for eth1"
    fi
  else
    info "NetworkManager not active; runtime routes removed only"
  fi
}

remove_journaling_config() {
  local journal_conf="/etc/systemd/journald.conf.d/99-persistent.conf"
  
  if [[ -f "$journal_conf" ]]; then
    info "Removing persistent journaling configuration: $journal_conf"
    rm -f "$journal_conf"
    
    # Optionally restart journald to apply changes
    read -r -p "Restart systemd-journald to apply changes? [y/N]: " restart_journal
    if [[ "${restart_journal,,}" == "y" ]]; then
      systemctl restart systemd-journald.service
      info "systemd-journald restarted"
    else
      warn "Journald configuration removed but service not restarted. Changes will apply after reboot."
    fi
  else
    warn "Journaling configuration not found: $journal_conf"
  fi
}

remove_user_account() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping user removal"
    return 0
  fi

  info "Removing user account: $u (including home directory)"
  userdel -r "$u" 2>/dev/null || warn "Failed to remove user $u"
}

main() {
  require_root

  echo "=========================================="
  echo "Cloudflared Container Uninstall Script"
  echo "=========================================="
  echo

  read -r -p "Enter the username that runs cloudflared: " CF_USER
  [[ -n "${CF_USER}" ]] || die "Username cannot be empty"

  if ! user_exists "${CF_USER}"; then
    warn "User ${CF_USER} does not exist. Some cleanup steps will be skipped."
  fi

  echo
  read -r -p "Was this server configured with 2 NICs and RFC1918 routes? [y/N]: " TWO_NICS
  TWO_NICS="${TWO_NICS,,}"

  echo
  echo "Starting uninstall process..."
  echo

  # 1. Stop and disable service
  stop_and_disable_service "${CF_USER}"

  # 2. Remove container and images
  remove_container_and_image "${CF_USER}"

  # 3. Remove Quadlet configuration
  remove_quadlet_files "${CF_USER}"

  # 4. Disable linger
  disable_linger "${CF_USER}"

  # 5. Remove sysctl configuration
  remove_sysctl_config

  # 6. Remove RFC1918 routes if configured
  if [[ "$TWO_NICS" == "y" ]]; then
    remove_rfc1918_routes
  else
    info "Skipping RFC1918 route removal (single NIC setup)"
  fi

  # 7. Remove journaling configuration
  echo
  read -r -p "Remove persistent journaling configuration? [y/N]: " REMOVE_JOURNAL
  if [[ "${REMOVE_JOURNAL,,}" == "y" ]]; then
    remove_journaling_config
  else
    info "Keeping persistent journaling configuration"
  fi

  # 8. Optionally remove user account
  echo
  read -r -p "Remove user account '${CF_USER}' and home directory? [y/N]: " REMOVE_USER
  if [[ "${REMOVE_USER,,}" == "y" ]]; then
    remove_user_account "${CF_USER}"
  else
    info "Keeping user account: ${CF_USER}"
  fi

  echo
  info "=========================================="
  info "Uninstall complete!"
  info "=========================================="
  echo
  info "The following items were processed:"
  echo "  - cloudflared service stopped and disabled"
  echo "  - Container and images removed"
  echo "  - Quadlet configuration removed"
  echo "  - User linger disabled"
  echo "  - Sysctl configuration removed"
  [[ "$TWO_NICS" == "y" ]] && echo "  - RFC1918 routes removed"
  [[ "${REMOVE_JOURNAL,,}" == "y" ]] && echo "  - Journaling configuration removed"
  [[ "${REMOVE_USER,,}" == "y" ]] && echo "  - User account removed"
  echo
  info "Note: Packages (podman, passt) were not removed. Uninstall manually if needed:"
  echo "  sudo dnf remove podman passt"
  echo
}

main "$@"
