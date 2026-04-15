#!/usr/bin/env bash
# install-brew-rtk.sh
# Installs Homebrew (Linux/macOS) and RTK (Rust Token Killer)
# https://github.com/mikezspam/scripts-tools

set -euo pipefail

BREW_ENV_LINE='eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"'

# ── helpers ────────────────────────────────────────────────────────────────────
info()    { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
success() { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn()    { printf '\033[1;33m!\033[0m %s\n' "$*"; }
die()     { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. Homebrew ────────────────────────────────────────────────────────────────
install_homebrew() {
  if command -v brew &>/dev/null; then
    success "Homebrew already installed: $(brew --version | head -1)"
    return
  fi

  info "Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

  # Activate brew in this shell session
  if [[ -f /home/linuxbrew/.linuxbrew/bin/brew ]]; then
    eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
  elif [[ -f /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi

  success "Homebrew installed: $(brew --version | head -1)"
}

# ── 2. Shell config persistence ────────────────────────────────────────────────
persist_brew_env() {
  # Only needed on Linux (macOS installer handles this itself)
  [[ "$(uname -s)" == "Linux" ]] || return 0

  local added=0
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [[ -f "$rc" ]] || continue
    if grep -qF 'linuxbrew' "$rc"; then
      success "brew shellenv already in $rc"
    else
      printf '\n# Homebrew (Linux)\n%s\n' "$BREW_ENV_LINE" >> "$rc"
      success "Added brew shellenv to $rc"
      added=1
    fi
  done

  if [[ $added -eq 0 ]] && ! grep -qF 'linuxbrew' "$HOME/.bashrc" 2>/dev/null; then
    printf '\n# Homebrew (Linux)\n%s\n' "$BREW_ENV_LINE" >> "$HOME/.bashrc"
    success "Added brew shellenv to ~/.bashrc"
  fi
}

# ── 3. RTK ─────────────────────────────────────────────────────────────────────
install_rtk() {
  if command -v rtk &>/dev/null; then
    success "RTK already installed: $(rtk --version)"
    return
  fi

  info "Installing rtk via Homebrew..."
  brew install rtk
  success "RTK installed: $(rtk --version)"
}

# ── 4. Verify ──────────────────────────────────────────────────────────────────
verify() {
  info "Verifying installation..."
  command -v brew &>/dev/null || die "brew not found after install"
  command -v rtk  &>/dev/null || die "rtk not found after install"

  success "brew: $(brew --version | head -1)"
  success "rtk:  $(rtk --version)"

  printf '\n'
  warn "To use brew/rtk in this terminal session, run:"
  printf '  %s\n\n' "$BREW_ENV_LINE"
  warn "New terminal sessions will pick it up automatically from your shell config."

  printf '\nRTK token savings:\n'
  rtk gain || true
}

# ── main ───────────────────────────────────────────────────────────────────────
main() {
  info "=== Homebrew + RTK installer ==="
  install_homebrew
  persist_brew_env
  install_rtk
  verify
}

main "$@"
