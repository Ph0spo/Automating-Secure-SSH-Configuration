#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Использование:
  sudo python3 harden_ssh.py -u USER [-k PUBKEY_FILE] [-c PARAMS_FILE] [--dry-run] [--force]
Требуется Python 3.6+, только стандартная библиотека.
"""

import datetime
import glob
import grp
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import traceback

#настройки
SCRIPT_NAME = os.path.basename(sys.argv[0])
SSHD_CONFIG = os.environ.get("SSHD_CONFIG") or "/etc/ssh/sshd_config"
DROPIN_DIR = os.environ.get("DROPIN_DIR") or "/etc/ssh/sshd_config.d"
DROPIN_FILE = os.path.join(DROPIN_DIR, "00-hardening.conf")
BACKUP_ROOT = os.environ.get("BACKUP_ROOT") or "/var/backups/ssh-hardening"
MARK_BEGIN = "# >>> ssh-hardening: managed block, do not edit >>>"
MARK_END = "# <<< ssh-hardening <<<"

# Целевые параметры sshd
PARAMS = [
    "PermitRootLogin no",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "PermitEmptyPasswords no",
    "PubkeyAuthentication yes",
    "MaxAuthTries 3",
    "LoginGraceTime 30",
    "StrictModes yes",
    "X11Forwarding no",
]

#вывод

if sys.stdout.isatty():
    C_OK, C_CHG, C_ERR, C_INF, C_0 = "\033[32m", "\033[33m", "\033[31m", "\033[36m", "\033[0m"
else:
    C_OK = C_CHG = C_ERR = C_INF = C_0 = ""

# состояние скрипта

TARGET_USER = ""
PUBKEY_FILE = ""
PARAMS_FILE = ""
DRY_RUN = False
FORCE = False
CHANGES = 0            
CONFIG_CHANGED = False
COMMITTED = False
BACKUP_DIR = ""
CREATED_FILES = []
BACKED_UP = []
SSHD_BIN = ""
SSH_DIR = ""
AUTH_KEYS = ""
EFFECTIVE = {}


def log_ok(msg):
    print("%s[ ok ]%s %s" % (C_OK, C_0, msg), flush=True)


def log_info(msg):
    print("%s[info]%s %s" % (C_INF, C_0, msg), flush=True)


def log_warn(msg):
    sys.stdout.flush()
    print("%s[warn]%s %s" % (C_CHG, C_0, msg), file=sys.stderr, flush=True)


def die(msg):
    sys.stdout.flush()
    print("%s[fail]%s %s" % (C_ERR, C_0, msg), file=sys.stderr, flush=True)
    sys.exit(1)


def apply(msg):
    global CHANGES
    CHANGES += 1
    if DRY_RUN:
        print("%s[plan]%s %s" % (C_CHG, C_0, msg), flush=True)
        return False
    print("%s[chg ]%s %s" % (C_CHG, C_0, msg), flush=True)
    return True


def usage(file=sys.stdout):
    print("""Использование: sudo {0} -u USER [опции]

  -u, --user USER       пользователь, которому разрешается вход по ключу (обязательно)
  -k, --pubkey FILE     файл с публичным ключом(ами) для добавления в authorized_keys
  -c, --config FILE     файл с параметрами sshd вместо встроенного набора
  -n, --dry-run         показать, что будет изменено, ничего не меняя
  -f, --force           отключить пароли, даже если у пользователя нет ни одного ключа
  -h, --help            эта справка

Пример:
  sudo {0} -u student -k ~/.ssh/id_ed25519.pub""".format(SCRIPT_NAME), file=file)


#помошники

def run(cmd, check=False, quiet_err=False, merge_err=False):
    stderr = subprocess.DEVNULL if quiet_err else (subprocess.STDOUT if merge_err else None)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=stderr,
                         universal_newlines=True)
    if check and res.returncode != 0:
        raise RuntimeError("команда завершилась с ошибкой (%d): %s" % (res.returncode, " ".join(cmd)))
    return res.returncode, res.stdout


def read_text(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def user_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def mode_str(path):
    return format(stat.S_IMODE(os.stat(path).st_mode), "o")


def owner_str(path):
    st = os.stat(path)
    try:
        user = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        user = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return "%s:%s" % (user, group)


def copy_preserve(src, dst):
    shutil.copy2(src, dst)
    st = os.stat(src)
    os.chown(dst, st.st_uid, st.st_gid)


#бэкап и откат

def backup_file(f):
    #Сохранить перед изменением
    global BACKUP_DIR
    if not os.path.exists(f):
        return
    if not BACKUP_DIR:
        os.makedirs(BACKUP_ROOT, exist_ok=True)
        os.chmod(BACKUP_ROOT, 0o700)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        BACKUP_DIR = tempfile.mkdtemp(prefix=stamp + "-", dir=BACKUP_ROOT)
    dst = BACKUP_DIR + f 
    if os.path.exists(dst):
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    copy_preserve(f, dst)
    BACKED_UP.append(f)


def rollback():
    log_warn("Откат изменений конфигурации sshd")
    for f in BACKED_UP:
        copy_preserve(BACKUP_DIR + f, f)
    for f in CREATED_FILES:
        if os.path.lexists(f):
            os.remove(f)


def on_error(exc):
    tb = traceback.extract_tb(exc.__traceback__)
    line = tb[-1].lineno if tb else "?"
    sys.stdout.flush()
    print("%s[fail]%s Ошибка в строке %s: %s" % (C_ERR, C_0, line, exc),
          file=sys.stderr, flush=True)
    if not COMMITTED and (BACKUP_DIR or CREATED_FILES):
        try:
            rollback()
        except Exception as e:
            print("%s[fail]%s Откат не удался: %s" % (C_ERR, C_0, e), file=sys.stderr)
    sys.exit(1)


def parse_args(args):
    global TARGET_USER, PUBKEY_FILE, PARAMS_FILE, DRY_RUN, FORCE
    args = list(args)
    while args:
        a = args.pop(0)
        if a in ("-u", "--user", "-k", "--pubkey", "-c", "--config"):
            if not args or not args[0]:
                usage(sys.stderr)
                die("не указано значение для %s" % a)
            value = args.pop(0)
            if a in ("-u", "--user"):
                TARGET_USER = value
            elif a in ("-k", "--pubkey"):
                PUBKEY_FILE = value
            else:
                PARAMS_FILE = value
        elif a in ("-n", "--dry-run"):
            DRY_RUN = True
        elif a in ("-f", "--force"):
            FORCE = True
        elif a in ("-h", "--help"):
            usage()
            sys.exit(0)
        else:
            usage(sys.stderr)
            die("Неизвестный аргумент: %s" % a)


def load_params():
    ##взять параметры sshd из файла
    global PARAMS
    if not PARAMS_FILE:
        return
    if not os.access(PARAMS_FILE, os.R_OK):
        die("Не удаётся прочитать %s" % PARAMS_FILE)
    params = []
    for raw in read_text(PARAMS_FILE).splitlines():
        line = " ".join(raw.split("#", 1)[0].split())   # без комментария и лишних пробелов
        if not line:
            continue
        if not re.match(r"^[A-Za-z][A-Za-z0-9]*\s+\S+$", line):
            die("Некорректная строка в %s: '%s' (нужно 'Параметр Значение')" % (PARAMS_FILE, line))
        params.append(line)
    if not params:
        die("В %s нет ни одного параметра" % PARAMS_FILE)
    PARAMS = params


#проверки до работы

def preflight():
    global SSHD_BIN
    if os.geteuid() != 0:
        die("Скрипт нужно запускать от root (sudo)")
    if not TARGET_USER:
        usage(sys.stderr)
        die("Укажите пользователя: -u USER")
    if TARGET_USER == "root":
        die("Пользователь для входа не может быть root")
    SSHD_BIN = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.access(SSHD_BIN, os.X_OK):
        die("Не найден sshd — установите openssh-server")
    if not os.path.isfile(SSHD_CONFIG):
        die("Не найден %s" % SSHD_CONFIG)
    if PUBKEY_FILE:
        if not os.access(PUBKEY_FILE, os.R_OK):
            die("Не удаётся прочитать %s" % PUBKEY_FILE)
        rc, _ = run(["ssh-keygen", "-l", "-f", PUBKEY_FILE], quiet_err=True)
        if rc != 0:
            die("%s не похож на публичный SSH-ключ" % PUBKEY_FILE)
    os.makedirs("/run/sshd", exist_ok=True)


def lockout_guard():
    if PUBKEY_FILE:
        log_ok("Ключ для входа будет установлен из %s" % PUBKEY_FILE)
        return
    n = 0
    try:
        keys = os.path.join(pwd.getpwnam(TARGET_USER).pw_dir, ".ssh", "authorized_keys")
        if os.path.isfile(keys) and os.path.getsize(keys) > 0:
            _, out = run(["ssh-keygen", "-l", "-f", keys], quiet_err=True)
            n = len([l for l in out.splitlines() if l.strip()])
    except KeyError:
        pass
    if n > 0:
        log_ok("У %s ключей в authorized_keys: %d" % (TARGET_USER, n))
    elif FORCE:
        log_warn("У %s нет ключей, но указан --force: вход по паролю будет отключён" % TARGET_USER)
    else:
        die("У %s нет ни одного ключа: после отключения паролей войти будет нельзя.\n"
            "       Передайте ключ через -k FILE (или --force, если доступ есть другим способом)."
            % TARGET_USER)


def ensure_host_keys():
    if glob.glob("/etc/ssh/ssh_host_*_key"):
        log_ok("Ключи хоста существуют")
    elif apply("Сгенерировать ключи хоста (ssh-keygen -A)"):
        run(["ssh-keygen", "-A"], check=True)


def read_effective():
    global EFFECTIVE
    EFFECTIVE = {}
    _, out = run([SSHD_BIN, "-T", "-f", SSHD_CONFIG], quiet_err=True)
    for line in out.splitlines():
        parts = line.split(None, 1)
        if parts:
            EFFECTIVE[parts[0]] = parts[1] if len(parts) > 1 else ""


def report_params():
    read_effective()
    log_info("Параметры sshd (текущее → нужное):")
    for p in PARAMS:
        key, want = p.split(None, 1)
        cur = EFFECTIVE.get(key.lower(), "?")
        if cur.lower() == want.lower():
            print("         %-30s %s" % (key, cur))
        else:
            print("         %-30s %s → %s" % (key, cur, want))


def ensure_user():
    if user_exists(TARGET_USER):
        log_ok("Пользователь %s существует" % TARGET_USER)
    elif apply("Создать пользователя %s" % TARGET_USER):
        run(["useradd", "-m", "-s", "/bin/bash", TARGET_USER], check=True)


def ensure_mode(path, mode, owner):
    cur = mode_str(path)
    if cur == mode:
        log_ok("%s: права %s" % (path, mode))
    elif apply("%s: права %s → %s" % (path, cur, mode)):
        os.chmod(path, int(mode, 8))
    cur = owner_str(path)
    if cur == owner:
        log_ok("%s: владелец %s" % (path, owner))
    elif apply("%s: владелец %s → %s" % (path, cur, owner)):
        user, group = owner.split(":", 1)
        shutil.chown(path, user, group)


def ensure_ssh_dir():
    global SSH_DIR, AUTH_KEYS
    if not user_exists(TARGET_USER):
        log_info("Пользователь будет создан — проверка ~/.ssh пропущена (dry-run)")
        return
    pw = pwd.getpwnam(TARGET_USER)
    home = pw.pw_dir
    group = grp.getgrgid(pw.pw_gid).gr_name
    SSH_DIR = os.path.join(home, ".ssh")
    AUTH_KEYS = os.path.join(SSH_DIR, "authorized_keys")

    hmode = stat.S_IMODE(os.stat(home).st_mode)
    if hmode & 0o022:
        if apply("%s: убрать запись для группы и остальных (%s)" % (home, format(hmode, "o"))):
            os.chmod(home, hmode & ~0o022)
    else:
        log_ok("%s: нет записи для группы и остальных" % home)

    if os.path.islink(SSH_DIR) or os.path.islink(AUTH_KEYS):
        die("%s или %s — символическая ссылка, проверьте вручную" % (SSH_DIR, AUTH_KEYS))

    if not os.path.isdir(SSH_DIR) and apply("Создать %s" % SSH_DIR):
        os.mkdir(SSH_DIR, 0o700)
        os.chmod(SSH_DIR, 0o700)
        shutil.chown(SSH_DIR, TARGET_USER, group)
    if not os.path.exists(AUTH_KEYS) and apply("Создать %s" % AUTH_KEYS):
        fd = os.open(AUTH_KEYS, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.chmod(AUTH_KEYS, 0o600)
        shutil.chown(AUTH_KEYS, TARGET_USER, group)
    if os.path.isdir(SSH_DIR):
        ensure_mode(SSH_DIR, "700", "%s:%s" % (TARGET_USER, group))
    if os.path.exists(AUTH_KEYS):
        ensure_mode(AUTH_KEYS, "600", "%s:%s" % (TARGET_USER, group))
    if not DRY_RUN and shutil.which("selinuxenabled") and run(["selinuxenabled"])[0] == 0:
        run(["restorecon", "-R", SSH_DIR], check=True)


def key_blob(line):
    words = line.split()
    for i in range(len(words) - 1):
        if re.match(r"^(ssh-|ecdsa-|sk-)", words[i]):
            return words[i + 1]
    return ""


def install_pubkeys():
    if not PUBKEY_FILE or not AUTH_KEYS:
        return
    for line in read_text(PUBKEY_FILE).splitlines():
        if not line or line.startswith("#"):
            continue
        blob = key_blob(line)
        if not blob:
            die("Не удалось разобрать ключ: %s" % line[:50])
        current = read_text(AUTH_KEYS) if os.path.isfile(AUTH_KEYS) else None
        if current is not None and blob in current:
            log_ok("Ключ уже в authorized_keys: %s…" % line[:40])
        elif apply("Добавить ключ в %s: %s…" % (AUTH_KEYS, line[:40])):
            with open(AUTH_KEYS, "a", encoding="utf-8", errors="surrogateescape") as f:
                if current and not current.endswith("\n"):
                    f.write("\n")
                f.write(line + "\n")


#онфигурация sshd 
def write_if_changed(f, content):
    #Записать файл атомарно
    global CONFIG_CHANGED
    content = content.rstrip("\n")
    if os.path.isfile(f) and read_text(f).rstrip("\n") == content:
        log_ok("%s актуален" % f)
        return
    if not apply("Записать %s" % f):
        return
    backup_file(f)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(f) + ".tmp.", dir=os.path.dirname(f))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as out:
            out.write(content + "\n")
        if os.path.exists(f):
            st = os.stat(f)
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
            os.chown(tmp, st.st_uid, st.st_gid)
        else:
            os.chmod(tmp, 0o644)
            CREATED_FILES.append(f)
        os.replace(tmp, f)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    CONFIG_CHANGED = True


def strip_managed_block():
    kept, skip = [], False
    for line in read_text(SSHD_CONFIG).splitlines():
        if line == MARK_BEGIN:
            skip = True
            continue
        if line == MARK_END:
            skip = False
            continue
        if not skip:
            kept.append(line)
    return "\n".join(kept).rstrip("\n")


def apply_sshd_config():
    body = "\n".join(PARAMS)
    config = read_text(SSHD_CONFIG)
    has_include = re.search(r"^[ \t]*Include[ \t]+(/etc/ssh/)?sshd_config\.d/", config, re.M)
    if os.path.isdir(DROPIN_DIR) and has_include:
        log_info("Режим: отдельный файл %s" % DROPIN_FILE)
        write_if_changed(DROPIN_FILE,
                         "# Управляется %s — ручные правки будут перезаписаны\n%s" % (SCRIPT_NAME, body))
        if MARK_BEGIN in config.splitlines():
            write_if_changed(SSHD_CONFIG, strip_managed_block())
    else:
        log_info("Режим: управляемый блок в начале %s (Include не найден)" % SSHD_CONFIG)
        write_if_changed(SSHD_CONFIG,
                         "%s\n%s\n%s\n%s" % (MARK_BEGIN, body, MARK_END, strip_managed_block()))


def where_defined(key):
    files = [SSHD_CONFIG]
    if os.path.isdir(DROPIN_DIR):
        for root, _, names in os.walk(DROPIN_DIR):
            files += [os.path.join(root, n) for n in sorted(names)]
    pattern = re.compile(r"^\s*%s\s" % re.escape(key), re.I)
    found = []
    for path in files:
        try:
            for n, line in enumerate(read_text(path).splitlines(), 1):
                if pattern.match(line):
                    found.append("%s:%d:%s" % (path, n, line))
        except OSError:
            pass
    return found


def validate_and_verify():
    if not CONFIG_CHANGED:
        return
    rc, out = run([SSHD_BIN, "-t", "-f", SSHD_CONFIG], merge_err=True)
    if rc != 0:
        rollback()
        die("sshd -t отклонил конфигурацию: %s" % out.strip())
    log_ok("Синтаксис конфигурации корректен (sshd -t)")

    read_effective()
    bad = False
    for p in PARAMS:
        key, want = p.split(None, 1)
        cur = EFFECTIVE.get(key.lower(), "")
        if cur.lower() != want.lower():
            bad = True
            log_warn("%s: фактически '%s', ожидалось '%s'. Где задан параметр:" % (key, cur, want))
            for line in where_defined(key):
                print(line, file=sys.stderr)
    if bad:
        rollback()
        die("Часть параметров перекрыта другими настройками — изменения откатаны")
    log_ok("Фактические значения совпадают с нужными (sshd -T)")


def reload_sshd():
    if not CONFIG_CHANGED:
        log_ok("Перечитывать конфигурацию sshd не нужно")
        return
    if os.path.isdir("/run/systemd/system") and shutil.which("systemctl"):
        for svc in ("ssh", "sshd"):
            if run(["systemctl", "is-active", "--quiet", svc])[0] == 0:
                run(["systemctl", "reload", svc], check=True)
                log_info("Выполнено: systemctl reload %s" % svc)
                return
    for pf in (EFFECTIVE.get("pidfile", ""), "/run/sshd.pid", "/var/run/sshd.pid"):
        if not pf or not os.access(pf, os.R_OK):
            continue
        try:
            pid = int(read_text(pf).strip())
            os.kill(pid, 0)
        except (ValueError, OSError):
            continue
        os.kill(pid, signal.SIGHUP)
        log_info("Отправлен SIGHUP процессу sshd (pid %d)" % pid)
        return
    log_warn("Запущенный sshd не найден — настройки применятся при следующем запуске")


def main(argv):
    global COMMITTED
    parse_args(argv)
    load_params()
    preflight()
    if DRY_RUN:
        log_info("Режим --dry-run: изменения не вносятся")

    lockout_guard()
    ensure_host_keys()
    report_params()
    ensure_user()
    ensure_ssh_dir()
    install_pubkeys()
    apply_sshd_config()
    validate_and_verify()
    COMMITTED = True
    reload_sshd()

    print()
    if DRY_RUN:
        log_info("Будет изменено: %d" % CHANGES)
    elif CHANGES:
        log_info("Готово. Изменений: %d" % CHANGES)
        if BACKUP_DIR:
            log_info("Резервная копия: %s" % BACKUP_DIR)
    else:
        log_info("Готово. Система уже в нужном состоянии, изменений нет")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt as e:
        on_error(e)
    except Exception as e:
        on_error(e)
