#!/usr/bin/env bash
# upgrade.sh — Update RCM to the latest version without losing data
#
# What this does, in order:
#   1. Records the current git commit
#   2. Backs up c2_audit.db  (operators, sessions, listeners, audit log)
#   3. Stashes local changes  (custom extensions, modules, config edits)
#   4. Stops the running container
#   5. git pull
#   6. Restores the stash
#   7. Calls start_docker.sh  (skips cert regen, fixes ownership, rebuilds, starts)
#
# Flags:
#   --skip-backup   Skip the database backup (faster, use when you know it is safe)
#
# Usage:
#   ./upgrade.sh
#   ./upgrade.sh --skip-backup

set -euo pipefail

# ── Colours (match start_docker.sh) ───────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; CLR_RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${CLR_RESET} $*"; }
success() { echo -e "${GREEN}[+]${CLR_RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${CLR_RESET} $*"; }
die()     { echo -e "${RED}[-] ERROR:${CLR_RESET} $*" >&2; exit 1; }

# ── Sanity checks ──────────────────────────────────────────────────────
command -v git    >/dev/null 2>&1 || die "git not found."
command -v docker >/dev/null 2>&1 || die "docker not found."
docker compose version >/dev/null 2>&1 || die "docker compose plugin not found."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

[[ -f Dockerfile          ]] || die "Dockerfile not found — run this from the RCM project root."
[[ -f docker-compose.yml  ]] || die "docker-compose.yml not found."
[[ -f start_docker.sh     ]] || die "start_docker.sh not found."
git rev-parse --git-dir >/dev/null 2>&1 || die "Not a git repository. Clone with 'git clone' to use upgrade.sh."

# ── Flags ──────────────────────────────────────────────────────────────
SKIP_BACKUP=false
for arg in "$@"; do
    case "$arg" in --skip-backup) SKIP_BACKUP=true ;; esac
done

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CLR_RESET}"
echo -e "${BOLD}  RCM Upgrade${CLR_RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CLR_RESET}"
echo ""

# ── Step 1: Record current version ────────────────────────────────────
FROM_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
FROM_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
info "Current version: ${FROM_COMMIT} on branch ${FROM_BRANCH}"

# ── Step 2: Backup database ────────────────────────────────────────────
if $SKIP_BACKUP; then
    warn "Database backup skipped (--skip-backup)."
elif [[ -f c2_audit.db ]]; then
    TS=$(date +%Y%m%d_%H%M%S)
    BACKUP="c2_audit.db.backup_${TS}"
    cp c2_audit.db "$BACKUP"
    success "Database backed up → ${BACKUP}"
else
    warn "c2_audit.db not found — nothing to back up."
fi

# ── Step 3: Stash local changes ────────────────────────────────────────
# This preserves edits to extensions/, modules/, and any config files
# so that git pull does not fail on modified tracked files.
# Untracked files (e.g. new custom .rhai scripts) are left untouched.
STASHED=false
if ! git diff --quiet || ! git diff --cached --quiet; then
    STASH_MSG="pre-upgrade $(date +%Y%m%d_%H%M%S)"
    warn "Local changes detected — stashing before pull."
    git stash push -m "$STASH_MSG"
    STASHED=true
    info "Stashed as: ${STASH_MSG}"
fi

# ── Step 4: Stop running container ────────────────────────────────────
if docker compose ps rcm-server 2>/dev/null | grep -qE "running|Up"; then
    info "Stopping rcm-server..."
    docker compose down
    success "Container stopped."
else
    info "Container not currently running."
fi

# ── Step 5: Pull latest code ───────────────────────────────────────────
info "Pulling from origin/${FROM_BRANCH}..."
git pull origin "$FROM_BRANCH"
TO_COMMIT=$(git rev-parse --short HEAD)

if [[ "$FROM_COMMIT" == "$TO_COMMIT" ]]; then
    success "Already up to date (${TO_COMMIT})."
else
    success "Updated: ${FROM_COMMIT} → ${TO_COMMIT}"
    echo ""
    echo -e "  ${CYAN}Changes:${CLR_RESET}"
    git log --oneline "${FROM_COMMIT}..${TO_COMMIT}" | sed 's/^/    /'
fi
echo ""

# ── Step 6: Restore stash ──────────────────────────────────────────────
if $STASHED; then
    info "Restoring local changes..."
    if git stash pop; then
        success "Local changes restored."
    else
        echo ""
        warn "Stash pop had merge conflicts."
        warn "Your local changes are saved in the stash — resolve manually:"
        echo ""
        echo "    git diff          # see conflicts"
        echo "    git stash show    # view stashed changes"
        echo "    git stash drop    # discard stash once resolved"
        echo ""
    fi
fi

# ── Step 7: Rebuild and start ──────────────────────────────────────────
# start_docker.sh handles:
#   - cert generation (skipped — certs already present)
#   - ownership fix (sudo chown on data dirs)
#   - docker compose build --no-cache
#   - docker compose up -d
#   - readiness wait + credential print
info "Rebuilding and starting server..."
echo ""
./start_docker.sh

# ── Done ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${CYAN}Upgraded${CLR_RESET} ${FROM_COMMIT} → ${TO_COMMIT}"
echo -e "  ${CYAN}Database backup${CLR_RESET} → ${BACKUP:-none}"
echo ""
