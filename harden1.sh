#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME=${0##*/}
SSHD_CONFIG=${SSHD_CONFIG:-/etc/ssh/sshd_config}
DROPIN_DIR=${DROPIN_DIR:-/etc/ssh/sshd_config.d}
DROPIN_FILE="$DROPIN_DIR/00-hardening.conf"
BACKUP_ROOT=${BACKUP_ROOT:-/var/backups/ssh-hardening}
MARK_BEGIN="# >>> ssh-hardening: managed block, do not edit >>>"
MARK_END="# <<< ssh-hardening <<<"

PARAMS=(
  "PermitRootLogin no"
  "PasswordAuthentication no"
  "KbdInteractiveAuthentication no"
  "PermitEmptyPasswords no"
  "PubkeyAuthentication yes"
  "MaxAuthTries 3"
  "LoginGraceTime 30"
  "StrictModes yes"
  "X11Forwarding no"
)

#вывод
if [[ -t 1 ]]; then
  C_OK=$'\e[32m' C_CHG=$'\e[33m' C_ERR=$'\e[31m' C_INF=$'\e[36m' C_0=$'\e[0m'
else
  C_OK='' C_CHG='' C_ERR='' C_INF='' C_0=''
fi

TARGET_USER='' PUBKEY_FILE='' PARAMS_FILE=''
DRY_RUN=0 FORCE=0
CHANGES=0 CONFIG_CHANGED=0 COMMITTED=0
BACKUP_DIR=''
CREATED_FILES=()
BACKED_UP=()

log_ok()   { printf '%s[ ok ]%s %s\n' "$C_OK"  "$C_0" "$*"; }
log_info() { printf '%s[info]%s %s\n' "$C_INF" "$C_0" "$*"; }
log_warn() { printf '%s[warn]%s %s\n' "$C_CHG" "$C_0" "$*" >&2; }
die()      { printf '%s[fail]%s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit 1; }

#Режим --dry-run(тест) только печатает
apply() {
  CHANGES=$((CHANGES + 1))
  if (( DRY_RUN )); then
    printf '%s[plan]%s %s\n' "$C_CHG" "$C_0" "$*"
    return 1
  fi
  printf '%s[chg ]%s %s\n' "$C_CHG" "$C_0" "$*"
}

usage() {
  cat <<EOF
Использование: sudo $SCRIPT_NAME -u USER [опции]

  -u, --user USER       пользователь, которому разрешается вход по ключу (обязательно)
  -k, --pubkey FILE     файл с публичным ключом(ами) для добавления в authorized_keys
  -c, --config FILE     файл с параметрами sshd вместо встроенного набора
  -n, --dry-run         показать, что будет изменено, ничего не меняя
  -f, --force           отключить пароли, даже если у пользователя нет ни одного ключа
  -h, --help            эта справка

Пример:
  sudo $SCRIPT_NAME -u student -k ~/.ssh/id_ed25519.pub
EOF
}

backup_file() {
  local f=$1
  [[ -e $f ]] || return 0
  if [[ -z $BACKUP_DIR ]]; then
    mkdir -p "$BACKUP_ROOT"
    chmod 700 "$BACKUP_ROOT"
    BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)-XXXX")
  fi
  [[ -e $BACKUP_DIR$f ]] && return 0
  cp -a --parents "$f" "$BACKUP_DIR/"
  BACKED_UP+=("$f")             
}

rollback() {
  log_warn "Откат изменений конфигурации sshd"
  local f
  for f in "${BACKED_UP[@]}"; do
    cp -a -- "$BACKUP_DIR$f" "$f"
  done
  for f in "${CREATED_FILES[@]}"; do
    rm -f -- "$f"
  done
}

on_error() {
  local line=$1
  printf '%s[fail]%s Ошибка в строке %s\n' "$C_ERR" "$C_0" "$line" >&2
  if (( ! COMMITTED )) && [[ -n $BACKUP_DIR || ${#CREATED_FILES[@]} -gt 0 ]]; then
    rollback
  fi
  exit 1
}
trap 'on_error $LINENO' ERR


parse_args() {
  while (( $# )); do
    case $1 in
      -u|--user)    TARGET_USER=${2:?"не указано значение для $1"}; shift 2 ;;
      -k|--pubkey)  PUBKEY_FILE=${2:?"не указано значение для $1"}; shift 2 ;;
      -c|--config)  PARAMS_FILE=${2:?"не указано значение для $1"}; shift 2 ;;
      -n|--dry-run) DRY_RUN=1; shift ;;
      -f|--force)   FORCE=1; shift ;;
      -h|--help)    usage; exit 0 ;;
      *)            usage >&2; die "Неизвестный аргумент: $1" ;;
    esac
  done
}

load_params() {
  [[ -n $PARAMS_FILE ]] || return 0
  [[ -r $PARAMS_FILE ]] || die "Не удаётся прочитать $PARAMS_FILE"
  PARAMS=()
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%%#*} #без комментов            
    line=$(echo "$line" | xargs) #без пробелов
    [[ -z $line ]] && continue
    [[ $line =~ ^[A-Za-z][A-Za-z0-9]*[[:space:]]+[^[:space:]]+$ ]] \
      || die "Некорректная строка в $PARAMS_FILE: '$line' (нужно 'Параметр Значение')"
    PARAMS+=("$line")
  done < "$PARAMS_FILE"
  (( ${#PARAMS[@]} )) || die "В $PARAMS_FILE нет ни одного параметра"
}

preflight() {
  [[ $EUID -eq 0 ]] || die "Скрипт нужно запускать от root (sudo)"
  [[ -n $TARGET_USER ]] || { usage >&2; die "Укажите пользователя: -u USER"; }
  [[ $TARGET_USER != root ]] || die "Пользователь для входа не может быть root"
  SSHD_BIN=$(command -v sshd || echo /usr/sbin/sshd)
  [[ -x $SSHD_BIN ]] || die "Не найден sshd — установите openssh-server"
  [[ -f $SSHD_CONFIG ]] || die "Не найден $SSHD_CONFIG"
  if [[ -n $PUBKEY_FILE ]]; then
    [[ -r $PUBKEY_FILE ]] || die "Не удаётся прочитать $PUBKEY_FILE"
    ssh-keygen -l -f "$PUBKEY_FILE" >/dev/null 2>&1 \
      || die "$PUBKEY_FILE не похож на публичный SSH-ключ"
  fi
  mkdir -p /run/sshd
}

ensure_host_keys() {
  if compgen -G "/etc/ssh/ssh_host_*_key" >/dev/null; then
    log_ok "Ключи хоста существуют"
  elif apply "Сгенерировать ключи хоста (ssh-keygen -A)"; then
    ssh-keygen -A >/dev/null
  fi
}

declare -A EFFECTIVE=()
read_effective() {
  EFFECTIVE=()
  local k v
  while read -r k v; do
    EFFECTIVE[$k]=$v
  done < <("$SSHD_BIN" -T -f "$SSHD_CONFIG" 2>/dev/null)
}

report_params() {
  read_effective
  log_info "Параметры sshd (текущее → нужное):"
  local p key want cur
  for p in "${PARAMS[@]}"; do
    read -r key want <<< "$p"
    cur=${EFFECTIVE[${key,,}]:-'?'}
    if [[ ${cur,,} == "${want,,}" ]]; then
      printf '         %-30s %s\n' "$key" "$cur"
    else
      printf '         %-30s %s → %s\n' "$key" "$cur" "$want"
    fi
  done
}

ensure_user() {
  if id -u "$TARGET_USER" >/dev/null 2>&1; then
    log_ok "Пользователь $TARGET_USER существует"
  elif apply "Создать пользователя $TARGET_USER"; then
    useradd -m -s /bin/bash "$TARGET_USER"
  fi
}

ensure_mode() {
  local path=$1 mode=$2 owner=$3 cur
  cur=$(stat -c %a "$path")
  if [[ $cur == "$mode" ]]; then
    log_ok "$path: права $mode"
  elif apply "$path: права $cur → $mode"; then
    chmod "$mode" "$path"
  fi
  cur=$(stat -c %U:%G "$path")
  if [[ $cur == "$owner" ]]; then
    log_ok "$path: владелец $owner"
  elif apply "$path: владелец $cur → $owner"; then
    chown "$owner" "$path"
  fi
}

ensure_ssh_dir() {
  if ! id -u "$TARGET_USER" >/dev/null 2>&1; then
    log_info "Пользователь будет создан — проверка ~/.ssh пропущена (dry-run)"
    return 0
  fi
  local home group
  home=$(getent passwd "$TARGET_USER" | cut -d: -f6)
  group=$(id -gn "$TARGET_USER")
  SSH_DIR="$home/.ssh"
  AUTH_KEYS="$SSH_DIR/authorized_keys"

  local hmode
  hmode=$(stat -c %a "$home")
  if (( 8#$hmode & 8#022 )); then
    if apply "$home: убрать запись для группы и остальных ($hmode)"; then
      chmod go-w "$home"
    fi
  else
    log_ok "$home: нет записи для группы и остальных"
  fi

  [[ ! -L $SSH_DIR && ! -L $AUTH_KEYS ]] \
    || die "$SSH_DIR или $AUTH_KEYS — символическая ссылка, проверьте вручную"

  if [[ ! -d $SSH_DIR ]] && apply "Создать $SSH_DIR"; then
    install -d -m 700 -o "$TARGET_USER" -g "$group" "$SSH_DIR"
  fi
  if [[ ! -e $AUTH_KEYS ]] && apply "Создать $AUTH_KEYS"; then
    install -m 600 -o "$TARGET_USER" -g "$group" /dev/null "$AUTH_KEYS"
  fi
  [[ -d $SSH_DIR ]]   && ensure_mode "$SSH_DIR"   700 "$TARGET_USER:$group"
  [[ -e $AUTH_KEYS ]] && ensure_mode "$AUTH_KEYS" 600 "$TARGET_USER:$group"
  
  # SELinux (RHEL/Fedora)
  if (( ! DRY_RUN )) && command -v selinuxenabled >/dev/null && selinuxenabled; then
    restorecon -R "$SSH_DIR"
  fi
  return 0
}

#сравнение ключа и без дублей
install_pubkeys() {
  [[ -n $PUBKEY_FILE && -n ${AUTH_KEYS:-} ]] || return 0
  local line blob
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == \#* ]] && continue
    blob=$(awk '{ for (i = 1; i < NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print $(i+1); exit } }' <<< "$line")
    [[ -n $blob ]] || die "Не удалось разобрать ключ: ${line:0:50}"
    if [[ -f $AUTH_KEYS ]] && grep -qF -- "$blob" "$AUTH_KEYS"; then
      log_ok "Ключ уже в authorized_keys: ${line:0:40}…"
    elif apply "Добавить ключ в $AUTH_KEYS: ${line:0:40}…"; then
      if [[ -s $AUTH_KEYS && -n $(tail -c1 "$AUTH_KEYS") ]]; then
        echo >> "$AUTH_KEYS"
      fi
      printf '%s\n' "$line" >> "$AUTH_KEYS"
    fi
  done < "$PUBKEY_FILE"
}

# Защита от потери доступа, до изменений
lockout_guard() {
  local n=0 home
  if [[ -n $PUBKEY_FILE ]]; then
    log_ok "Ключ для входа будет установлен из $PUBKEY_FILE"
    return 0
  fi
  if home=$(getent passwd "$TARGET_USER" | cut -d: -f6) && [[ -s $home/.ssh/authorized_keys ]]; then
    n=$(ssh-keygen -l -f "$home/.ssh/authorized_keys" 2>/dev/null | wc -l || true)
  fi
  if (( n > 0 )); then
    log_ok "У $TARGET_USER ключей в authorized_keys: $n"
  elif (( FORCE )); then
    log_warn "У $TARGET_USER нет ключей, но указан --force: вход по паролю будет отключён"
  else
    die "У $TARGET_USER нет ни одного ключа: после отключения паролей войти будет нельзя.
       Передайте ключ через -k FILE (или --force, если доступ есть другим способом)."
  fi
}

# Записать файл,если содержимое изменилось 
write_if_changed() {
  local f=$1 content=$2 tmp
  if [[ -f $f && "$(cat "$f")" == "$content" ]]; then
    log_ok "$f актуален"
    return 0
  fi
  apply "Записать $f" || return 0
  backup_file "$f"
  tmp=$(mktemp "$f.tmp.XXXXXX")
  printf '%s\n' "$content" > "$tmp"
  if [[ -e $f ]]; then
    chmod --reference="$f" "$tmp"
    chown --reference="$f" "$tmp"
  else
    chmod 644 "$tmp"
    CREATED_FILES+=("$f")
  fi
  mv -f "$tmp" "$f"
  CONFIG_CHANGED=1
}

strip_managed_block() {
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" \
    '$0 == b { skip = 1; next } $0 == e { skip = 0; next } !skip' "$SSHD_CONFIG"
}

apply_sshd_config() {
  local body
  body=$(printf '%s\n' "${PARAMS[@]}")
  if [[ -d $DROPIN_DIR ]] \
     && grep -qE '^[[:space:]]*Include[[:space:]]+(/etc/ssh/)?sshd_config\.d/' "$SSHD_CONFIG"; then
    log_info "Режим: отдельный файл $DROPIN_FILE"
    write_if_changed "$DROPIN_FILE" "# Управляется $SCRIPT_NAME — ручные правки будут перезаписаны
$body"
    # Если раньше использовался блок в основном конфиге — убрать его.
    if grep -qxF -- "$MARK_BEGIN" "$SSHD_CONFIG"; then
      write_if_changed "$SSHD_CONFIG" "$(strip_managed_block)"
    fi
  else
    log_info "Режим: управляемый блок в начале $SSHD_CONFIG (Include не найден)"
    write_if_changed "$SSHD_CONFIG" "$MARK_BEGIN
$body
$MARK_END
$(strip_managed_block)"
  fi
}

validate_and_verify() {
  (( CONFIG_CHANGED )) || return 0
  local out
  if ! out=$("$SSHD_BIN" -t -f "$SSHD_CONFIG" 2>&1); then
    rollback
    die "sshd -t отклонил конфигурацию: $out"
  fi
  log_ok "Синтаксис конфигурации корректен (sshd -t)"

  # Проверка факт. значеиний. Могут быть перекрыты
  read_effective
  local p key want cur bad=0
  for p in "${PARAMS[@]}"; do
    read -r key want <<< "$p"
    cur=${EFFECTIVE[${key,,}]:-}
    if [[ ${cur,,} != "${want,,}" ]]; then
      bad=1
      log_warn "$key: фактически '$cur', ожидалось '$want'. Где задан параметр:"
      grep -RinE "^[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG" "$DROPIN_DIR" >&2 2>/dev/null || true
    fi
  done
  if (( bad )); then
    rollback
    die "Часть параметров перекрыта другими настройками — изменения откатаны"
  fi
  log_ok "Фактические значения совпадают с нужными (sshd -T)"
}

reload_sshd() {
  if (( ! CONFIG_CHANGED )); then
    log_ok "Перечитывать конфигурацию sshd не нужно"
    return 0
  fi
  local svc pf pid
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
    for svc in ssh sshd; do
      if systemctl is-active --quiet "$svc"; then
        systemctl reload "$svc"
        log_info "Выполнено: systemctl reload $svc"
        return 0
      fi
    done
  fi

  for pf in "${EFFECTIVE[pidfile]:-}" /run/sshd.pid /var/run/sshd.pid; do
    if [[ -n $pf && -r $pf ]]; then
      pid=$(<"$pf")
      if kill -0 "$pid" 2>/dev/null; then
        kill -HUP "$pid"
        log_info "Отправлен SIGHUP процессу sshd (pid $pid)"
        return 0
      fi
    fi
  done
  log_warn "Запущенный sshd не найден — настройки применятся при следующем запуске"
}

main() {
  parse_args "$@"
  load_params
  preflight
  if (( DRY_RUN )); then
    log_info "Режим --dry-run: изменения не вносятся"
  fi

  lockout_guard
  ensure_host_keys
  report_params
  ensure_user
  ensure_ssh_dir
  install_pubkeys
  apply_sshd_config
  validate_and_verify
  COMMITTED=1
  reload_sshd

  echo
  if (( DRY_RUN )); then
    log_info "Будет изменено: $CHANGES"
  elif (( CHANGES )); then
    log_info "Готово. Изменений: $CHANGES"
    if [[ -n $BACKUP_DIR ]]; then
      log_info "Резервная копия: $BACKUP_DIR"
    fi
  else
    log_info "Готово. Система уже в нужном состоянии, изменений нет"
  fi
}

main "$@"
