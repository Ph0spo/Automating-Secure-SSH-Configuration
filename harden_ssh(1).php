#!/usr/bin/env php
<?php
if (PHP_SAPI !== 'cli') {
    exit("Запускайте из командной строки: php harden_ssh.php ...\n");
}

$SCRIPT_NAME = basename($argv[0]);
$SSHD_CONFIG = getenv('SSHD_CONFIG') ?: '/etc/ssh/sshd_config';
$DROPIN_DIR  = getenv('DROPIN_DIR') ?: '/etc/ssh/sshd_config.d';
$DROPIN_FILE = "$DROPIN_DIR/00-hardening.conf";
$BACKUP_ROOT = getenv('BACKUP_ROOT') ?: '/var/backups/ssh-hardening';
const MARK_BEGIN = '# >>> ssh-hardening: managed block, do not edit >>>';
const MARK_END   = '# <<< ssh-hardening <<<';

$PARAMS = [
    'PermitRootLogin no',
    'PasswordAuthentication no',
    'KbdInteractiveAuthentication no',
    'PermitEmptyPasswords no',
    'PubkeyAuthentication yes',
    'MaxAuthTries 3',
    'LoginGraceTime 30',
    'StrictModes yes',
    'X11Forwarding no',
];

if (stream_isatty(STDOUT)) {
    [$C_OK, $C_CHG, $C_ERR, $C_INF, $C_0] = ["\e[32m", "\e[33m", "\e[31m", "\e[36m", "\e[0m"];
} else {
    [$C_OK, $C_CHG, $C_ERR, $C_INF, $C_0] = ['', '', '', '', ''];
}

$TARGET_USER = ''; $PUBKEY_FILE = ''; $PARAMS_FILE = '';
$DRY_RUN = false; $FORCE = false;
$CHANGES = 0;
$CONFIG_CHANGED = false;
$COMMITTED = false;
$BACKUP_DIR = '';
$CREATED_FILES = [];
$BACKED_UP = [];
$SSHD_BIN = ''; $SSH_DIR = ''; $AUTH_KEYS = '';
$EFFECTIVE = [];

function log_ok($msg)   { global $C_OK, $C_0;  fwrite(STDOUT, "{$C_OK}[ ok ]{$C_0} $msg\n"); }
function log_info($msg) { global $C_INF, $C_0; fwrite(STDOUT, "{$C_INF}[info]{$C_0} $msg\n"); }
function log_warn($msg) { global $C_CHG, $C_0; fwrite(STDERR, "{$C_CHG}[warn]{$C_0} $msg\n"); }

function fail($msg)
{
    global $C_ERR, $C_0;
    fwrite(STDERR, "{$C_ERR}[fail]{$C_0} $msg\n");
    exit(1);
}

function apply($msg)
{
    global $CHANGES, $DRY_RUN, $C_CHG, $C_0;
    $CHANGES++;
    if ($DRY_RUN) {
        fwrite(STDOUT, "{$C_CHG}[plan]{$C_0} $msg\n");
        return false;
    }
    fwrite(STDOUT, "{$C_CHG}[chg ]{$C_0} $msg\n");
    return true;
}

function usage($stream = STDOUT)
{
    global $SCRIPT_NAME;
    fwrite($stream, <<<EOT
Использование: sudo $SCRIPT_NAME -u USER [опции]

  -u, --user USER       пользователь, которому разрешается вход по ключу (обязательно)
  -k, --pubkey FILE     файл с публичным ключом(ами) для добавления в authorized_keys
  -c, --config FILE     файл с параметрами sshd вместо встроенного набора
  -n, --dry-run         показать, что будет изменено, ничего не меняя
  -f, --force           отключить пароли, даже если у пользователя нет ни одного ключа
  -h, --help            эта справка

Пример:
  sudo $SCRIPT_NAME -u student -k ~/.ssh/id_ed25519.pub

EOT
    );
}

function run(array $cmd, $check = false, $quietErr = false, $mergeErr = false)
{
    $spec = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w']];
    if ($quietErr)      { $spec[2] = ['file', '/dev/null', 'w']; }
    elseif ($mergeErr)  { $spec[2] = ['redirect', 1]; }
    else                { $spec[2] = STDERR; }
    $proc = proc_open($cmd, $spec, $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('не удалось запустить: ' . implode(' ', $cmd));
    }
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $rc = proc_close($proc);
    if ($check && $rc !== 0) {
        throw new RuntimeException("команда завершилась с ошибкой ($rc): " . implode(' ', $cmd));
    }
    return [$rc, $out];
}

function which($name)
{
    foreach (explode(':', getenv('PATH') ?: '/usr/sbin:/usr/bin:/sbin:/bin') as $dir) {
        if ($dir !== '' && is_file("$dir/$name") && is_executable("$dir/$name")) {
            return "$dir/$name";
        }
    }
    return '';
}

function user_info($name)
{
    [$rc, $out] = run(['getent', 'passwd', $name], false, true);
    if ($rc !== 0 || trim($out) === '') {
        return null;
    }
    $f = explode(':', trim($out));
    return ['uid' => (int)$f[2], 'gid' => (int)$f[3], 'home' => $f[5]];
}

function user_group($name)
{
    [, $out] = run(['id', '-gn', $name], true);
    return trim($out);
}

function mode_str($path)
{
    clearstatcache(true, $path);
    return decoct(fileperms($path) & 07777);
}

function owner_str($path)
{
    [, $out] = run(['stat', '-c', '%U:%G', $path], true);
    return trim($out);
}

function cut($s, $n)
{
    return preg_match('/^.{0,' . (int)$n . '}/us', $s, $m) ? $m[0] : substr($s, 0, $n);
}

function copy_preserve($src, $dst)
{
    copy($src, $dst);
    clearstatcache(true, $src);
    $st = stat($src);
    chmod($dst, $st['mode'] & 07777);
    chown($dst, $st['uid']);
    chgrp($dst, $st['gid']);
    touch($dst, $st['mtime'], $st['atime']);
}

function random_suffix($len)
{
    return substr(bin2hex(random_bytes($len)), 0, $len);
}

function backup_file($f)
{
    global $BACKUP_DIR, $BACKUP_ROOT, $BACKED_UP;
    if (!file_exists($f)) {
        return;
    }
    if ($BACKUP_DIR === '') {
        if (!is_dir($BACKUP_ROOT)) {
            mkdir($BACKUP_ROOT, 0700, true);
        }
        chmod($BACKUP_ROOT, 0700);
        $stamp = trim(run(['date', '+%Y%m%d-%H%M%S'], true)[1]);
        do {
            $dir = $BACKUP_ROOT . '/' . $stamp . '-' . random_suffix(4);
        } while (file_exists($dir));
        mkdir($dir, 0700);
        $BACKUP_DIR = $dir;
    }
    $dst = $BACKUP_DIR . $f;
    if (file_exists($dst)) {
        return;
    }
    if (!is_dir(dirname($dst))) {
        mkdir(dirname($dst), 0755, true);
    }
    copy_preserve($f, $dst);
    $BACKED_UP[] = $f;
}

function rollback()
{
    global $BACKUP_DIR, $BACKED_UP, $CREATED_FILES;
    log_warn('Откат изменений конфигурации sshd');
    foreach ($BACKED_UP as $f) {
        copy_preserve($BACKUP_DIR . $f, $f);
    }
    foreach ($CREATED_FILES as $f) {
        if (file_exists($f) || is_link($f)) {
            unlink($f);
        }
    }
}

function on_error(Throwable $e)
{
    global $COMMITTED, $BACKUP_DIR, $CREATED_FILES, $C_ERR, $C_0;
    fwrite(STDERR, "{$C_ERR}[fail]{$C_0} Ошибка в строке {$e->getLine()}: {$e->getMessage()}\n");
    if (!$COMMITTED && ($BACKUP_DIR !== '' || count($CREATED_FILES) > 0)) {
        try {
            rollback();
        } catch (Throwable $e2) {
            fwrite(STDERR, "{$C_ERR}[fail]{$C_0} Откат не удался: {$e2->getMessage()}\n");
        }
    }
    exit(1);
}

function parse_args(array $args)
{
    global $TARGET_USER, $PUBKEY_FILE, $PARAMS_FILE, $DRY_RUN, $FORCE;
    while ($args) {
        $a = array_shift($args);
        switch ($a) {
            case '-u': case '--user':
            case '-k': case '--pubkey':
            case '-c': case '--config':
                if (!$args || $args[0] === '') {
                    usage(STDERR);
                    fail("не указано значение для $a");
                }
                $value = array_shift($args);
                if ($a === '-u' || $a === '--user')        { $TARGET_USER = $value; }
                elseif ($a === '-k' || $a === '--pubkey')  { $PUBKEY_FILE = $value; }
                else                                       { $PARAMS_FILE = $value; }
                break;
            case '-n': case '--dry-run':
                $DRY_RUN = true;
                break;
            case '-f': case '--force':
                $FORCE = true;
                break;
            case '-h': case '--help':
                usage();
                exit(0);
            default:
                usage(STDERR);
                fail("Неизвестный аргумент: $a");
        }
    }
}

function load_params()
{
    global $PARAMS_FILE, $PARAMS;
    if ($PARAMS_FILE === '') {
        return;
    }
    if (!is_readable($PARAMS_FILE)) {
        fail("Не удаётся прочитать $PARAMS_FILE");
    }
    $params = [];
    foreach (preg_split('/\R/', file_get_contents($PARAMS_FILE)) as $raw) {
        $line = explode('#', $raw, 2)[0];
        $line = trim(preg_replace('/\s+/', ' ', $line));
        if ($line === '') {
            continue;
        }
        if (!preg_match('/^[A-Za-z][A-Za-z0-9]*\s+\S+$/', $line)) {
            fail("Некорректная строка в $PARAMS_FILE: '$line' (нужно 'Параметр Значение')");
        }
        $params[] = $line;
    }
    if (!$params) {
        fail("В $PARAMS_FILE нет ни одного параметра");
    }
    $PARAMS = $params;
}

function preflight()
{
    global $TARGET_USER, $SSHD_BIN, $SSHD_CONFIG, $PUBKEY_FILE;
    $euid = function_exists('posix_geteuid') ? posix_geteuid() : (int)trim(run(['id', '-u'])[1]);
    if ($euid !== 0) {
        fail('Скрипт нужно запускать от root (sudo)');
    }
    if ($TARGET_USER === '') {
        usage(STDERR);
        fail('Укажите пользователя: -u USER');
    }
    if ($TARGET_USER === 'root') {
        fail('Пользователь для входа не может быть root');
    }
    $SSHD_BIN = which('sshd') ?: '/usr/sbin/sshd';
    if (!is_executable($SSHD_BIN)) {
        fail('Не найден sshd — установите openssh-server');
    }
    if (!is_file($SSHD_CONFIG)) {
        fail("Не найден $SSHD_CONFIG");
    }
    if ($PUBKEY_FILE !== '') {
        if (!is_readable($PUBKEY_FILE)) {
            fail("Не удаётся прочитать $PUBKEY_FILE");
        }
        if (run(['ssh-keygen', '-l', '-f', $PUBKEY_FILE], false, true)[0] !== 0) {
            fail("$PUBKEY_FILE не похож на публичный SSH-ключ");
        }
    }
    if (!is_dir('/run/sshd')) {
        mkdir('/run/sshd', 0755, true);
    }
}

function lockout_guard()
{
    global $PUBKEY_FILE, $TARGET_USER, $FORCE;
    if ($PUBKEY_FILE !== '') {
        log_ok("Ключ для входа будет установлен из $PUBKEY_FILE");
        return;
    }
    $n = 0;
    $u = user_info($TARGET_USER);
    if ($u) {
        $keys = $u['home'] . '/.ssh/authorized_keys';
        if (is_file($keys) && filesize($keys) > 0) {
            [, $out] = run(['ssh-keygen', '-l', '-f', $keys], false, true);
            $n = count(array_filter(explode("\n", $out), function ($l) { return trim($l) !== ''; }));
        }
    }
    if ($n > 0) {
        log_ok("У $TARGET_USER ключей в authorized_keys: $n");
    } elseif ($FORCE) {
        log_warn("У $TARGET_USER нет ключей, но указан --force: вход по паролю будет отключён");
    } else {
        fail("У $TARGET_USER нет ни одного ключа: после отключения паролей войти будет нельзя.\n"
           . "       Передайте ключ через -k FILE (или --force, если доступ есть другим способом).");
    }
}

function ensure_host_keys()
{
    if (glob('/etc/ssh/ssh_host_*_key')) {
        log_ok('Ключи хоста существуют');
    } elseif (apply('Сгенерировать ключи хоста (ssh-keygen -A)')) {
        run(['ssh-keygen', '-A'], true);
    }
}

function read_effective()
{
    global $EFFECTIVE, $SSHD_BIN, $SSHD_CONFIG;
    $EFFECTIVE = [];
    [, $out] = run([$SSHD_BIN, '-T', '-f', $SSHD_CONFIG], false, true);
    foreach (explode("\n", $out) as $line) {
        $parts = preg_split('/\s+/', trim($line), 2);
        if ($parts[0] !== '') {
            $EFFECTIVE[$parts[0]] = $parts[1] ?? '';
        }
    }
}

function report_params()
{
    global $PARAMS, $EFFECTIVE;
    read_effective();
    log_info('Параметры sshd (текущее → нужное):');
    foreach ($PARAMS as $p) {
        [$key, $want] = preg_split('/\s+/', $p, 2);
        $cur = $EFFECTIVE[strtolower($key)] ?? '?';
        if (strtolower($cur) === strtolower($want)) {
            printf("         %-30s %s\n", $key, $cur);
        } else {
            printf("         %-30s %s → %s\n", $key, $cur, $want);
        }
    }
}

function ensure_user()
{
    global $TARGET_USER;
    if (user_info($TARGET_USER)) {
        log_ok("Пользователь $TARGET_USER существует");
    } elseif (apply("Создать пользователя $TARGET_USER")) {
        run(['useradd', '-m', '-s', '/bin/bash', $TARGET_USER], true);
    }
}

function ensure_mode($path, $mode, $owner)
{
    $cur = mode_str($path);
    if ($cur === $mode) {
        log_ok("$path: права $mode");
    } elseif (apply("$path: права $cur → $mode")) {
        chmod($path, octdec($mode));
    }
    $cur = owner_str($path);
    if ($cur === $owner) {
        log_ok("$path: владелец $owner");
    } elseif (apply("$path: владелец $cur → $owner")) {
        [$user, $group] = explode(':', $owner, 2);
        chown($path, $user);
        chgrp($path, $group);
    }
}

function ensure_ssh_dir()
{
    global $TARGET_USER, $SSH_DIR, $AUTH_KEYS, $DRY_RUN;
    $u = user_info($TARGET_USER);
    if (!$u) {
        log_info('Пользователь будет создан — проверка ~/.ssh пропущена (dry-run)');
        return;
    }
    $home = $u['home'];
    $group = user_group($TARGET_USER);
    $SSH_DIR = "$home/.ssh";
    $AUTH_KEYS = "$SSH_DIR/authorized_keys";

    clearstatcache(true, $home);
    $hmode = fileperms($home) & 07777;
    if ($hmode & 0022) {
        if (apply("$home: убрать запись для группы и остальных (" . decoct($hmode) . ')')) {
            chmod($home, $hmode & ~0022);
        }
    } else {
        log_ok("$home: нет записи для группы и остальных");
    }

    if (is_link($SSH_DIR) || is_link($AUTH_KEYS)) {
        fail("$SSH_DIR или $AUTH_KEYS — символическая ссылка, проверьте вручную");
    }

    if (!is_dir($SSH_DIR) && apply("Создать $SSH_DIR")) {
        mkdir($SSH_DIR, 0700);
        chmod($SSH_DIR, 0700);
        chown($SSH_DIR, $TARGET_USER);
        chgrp($SSH_DIR, $group);
    }
    if (!file_exists($AUTH_KEYS) && apply("Создать $AUTH_KEYS")) {
        $h = fopen($AUTH_KEYS, 'x');
        fclose($h);
        chmod($AUTH_KEYS, 0600);
        chown($AUTH_KEYS, $TARGET_USER);
        chgrp($AUTH_KEYS, $group);
    }
    if (is_dir($SSH_DIR)) {
        ensure_mode($SSH_DIR, '700', "$TARGET_USER:$group");
    }
    if (file_exists($AUTH_KEYS)) {
        ensure_mode($AUTH_KEYS, '600', "$TARGET_USER:$group");
    }

    if (!$DRY_RUN && which('selinuxenabled') !== '' && run(['selinuxenabled'])[0] === 0) {
        run(['restorecon', '-R', $SSH_DIR], true);
    }
}

function key_blob($line)
{
    $words = preg_split('/\s+/', trim($line));
    for ($i = 0; $i < count($words) - 1; $i++) {
        if (preg_match('/^(ssh-|ecdsa-|sk-)/', $words[$i])) {
            return $words[$i + 1];
        }
    }
    return '';
}

function install_pubkeys()
{
    global $PUBKEY_FILE, $AUTH_KEYS;
    if ($PUBKEY_FILE === '' || $AUTH_KEYS === '') {
        return;
    }
    foreach (preg_split('/\R/', file_get_contents($PUBKEY_FILE)) as $line) {
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        $blob = key_blob($line);
        if ($blob === '') {
            fail('Не удалось разобрать ключ: ' . cut($line, 50));
        }
        $current = is_file($AUTH_KEYS) ? file_get_contents($AUTH_KEYS) : null;
        if ($current !== null && strpos($current, $blob) !== false) {
            log_ok('Ключ уже в authorized_keys: ' . cut($line, 40) . '…');
        } elseif (apply("Добавить ключ в $AUTH_KEYS: " . cut($line, 40) . '…')) {
            $add = '';
            if ($current !== null && $current !== '' && substr($current, -1) !== "\n") {
                $add = "\n";
            }
            file_put_contents($AUTH_KEYS, $add . $line . "\n", FILE_APPEND);
        }
    }
}

function write_if_changed($f, $content)
{
    global $CONFIG_CHANGED, $CREATED_FILES;
    $content = rtrim($content, "\n");
    if (is_file($f) && rtrim(file_get_contents($f), "\n") === $content) {
        log_ok("$f актуален");
        return;
    }
    if (!apply("Записать $f")) {
        return;
    }
    backup_file($f);
    do {
        $tmp = "$f.tmp." . random_suffix(6);
        $h = @fopen($tmp, 'x');
    } while ($h === false && file_exists($tmp));
    if ($h === false) {
        throw new RuntimeException("не удалось создать временный файл рядом с $f");
    }
    try {
        chmod($tmp, 0600);
        fwrite($h, $content . "\n");
        fclose($h);
        if (file_exists($f)) {
            clearstatcache(true, $f);
            $st = stat($f);
            chmod($tmp, $st['mode'] & 07777);
            chown($tmp, $st['uid']);
            chgrp($tmp, $st['gid']);
        } else {
            chmod($tmp, 0644);
            $CREATED_FILES[] = $f;
        }
        rename($tmp, $f);
    } catch (Throwable $e) {
        if (file_exists($tmp)) {
            unlink($tmp);
        }
        throw $e;
    }
    $CONFIG_CHANGED = true;
}

function strip_managed_block()
{
    global $SSHD_CONFIG;
    $kept = [];
    $skip = false;
    foreach (explode("\n", file_get_contents($SSHD_CONFIG)) as $line) {
        if ($line === MARK_BEGIN) { $skip = true;  continue; }
        if ($line === MARK_END)   { $skip = false; continue; }
        if (!$skip) {
            $kept[] = $line;
        }
    }
    return rtrim(implode("\n", $kept), "\n");
}

function apply_sshd_config()
{
    global $PARAMS, $SSHD_CONFIG, $DROPIN_DIR, $DROPIN_FILE, $SCRIPT_NAME;
    $body = implode("\n", $PARAMS);
    $config = file_get_contents($SSHD_CONFIG);
    $hasInclude = preg_match('~^[ \t]*Include[ \t]+(/etc/ssh/)?sshd_config\.d/~m', $config);
    if (is_dir($DROPIN_DIR) && $hasInclude) {
        log_info("Режим: отдельный файл $DROPIN_FILE");
        write_if_changed($DROPIN_FILE, "# Управляется $SCRIPT_NAME — ручные правки будут перезаписаны\n$body");
        if (in_array(MARK_BEGIN, explode("\n", $config), true)) {
            write_if_changed($SSHD_CONFIG, strip_managed_block());
        }
    } else {
        log_info("Режим: управляемый блок в начале $SSHD_CONFIG (Include не найден)");
        write_if_changed($SSHD_CONFIG, MARK_BEGIN . "\n$body\n" . MARK_END . "\n" . strip_managed_block());
    }
}

function where_defined($key)
{
    global $SSHD_CONFIG, $DROPIN_DIR;
    $files = [$SSHD_CONFIG];
    if (is_dir($DROPIN_DIR)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($DROPIN_DIR, FilesystemIterator::SKIP_DOTS));
        $more = [];
        foreach ($it as $file) {
            $more[] = $file->getPathname();
        }
        sort($more);
        $files = array_merge($files, $more);
    }
    $found = [];
    foreach ($files as $path) {
        if (!is_readable($path)) {
            continue;
        }
        foreach (explode("\n", file_get_contents($path)) as $i => $line) {
            if (preg_match('/^\s*' . preg_quote($key, '/') . '\s/i', $line)) {
                $found[] = "$path:" . ($i + 1) . ":$line";
            }
        }
    }
    return $found;
}

function validate_and_verify()
{
    global $CONFIG_CHANGED, $SSHD_BIN, $SSHD_CONFIG, $PARAMS, $EFFECTIVE;
    if (!$CONFIG_CHANGED) {
        return;
    }
    [$rc, $out] = run([$SSHD_BIN, '-t', '-f', $SSHD_CONFIG], false, false, true);
    if ($rc !== 0) {
        rollback();
        fail('sshd -t отклонил конфигурацию: ' . trim($out));
    }
    log_ok('Синтаксис конфигурации корректен (sshd -t)');

    read_effective();
    $bad = false;
    foreach ($PARAMS as $p) {
        [$key, $want] = preg_split('/\s+/', $p, 2);
        $cur = $EFFECTIVE[strtolower($key)] ?? '';
        if (strtolower($cur) !== strtolower($want)) {
            $bad = true;
            log_warn("$key: фактически '$cur', ожидалось '$want'. Где задан параметр:");
            foreach (where_defined($key) as $line) {
                fwrite(STDERR, "$line\n");
            }
        }
    }
    if ($bad) {
        rollback();
        fail('Часть параметров перекрыта другими настройками — изменения откатаны');
    }
    log_ok('Фактические значения совпадают с нужными (sshd -T)');
}

function process_alive($pid)
{
    if (function_exists('posix_kill')) {
        return posix_kill($pid, 0);
    }
    return run(['kill', '-0', (string)$pid], false, true)[0] === 0;
}

function reload_sshd()
{
    global $CONFIG_CHANGED, $EFFECTIVE;
    if (!$CONFIG_CHANGED) {
        log_ok('Перечитывать конфигурацию sshd не нужно');
        return;
    }
    if (is_dir('/run/systemd/system') && which('systemctl') !== '') {
        foreach (['ssh', 'sshd'] as $svc) {
            if (run(['systemctl', 'is-active', '--quiet', $svc])[0] === 0) {
                run(['systemctl', 'reload', $svc], true);
                log_info("Выполнено: systemctl reload $svc");
                return;
            }
        }
    }
    foreach ([$EFFECTIVE['pidfile'] ?? '', '/run/sshd.pid', '/var/run/sshd.pid'] as $pf) {
        if ($pf === '' || !is_readable($pf)) {
            continue;
        }
        $pid = trim(file_get_contents($pf));
        if (!ctype_digit($pid) || !process_alive((int)$pid)) {
            continue;
        }
        run(['kill', '-HUP', $pid], true);
        log_info("Отправлен SIGHUP процессу sshd (pid $pid)");
        return;
    }
    log_warn('Запущенный sshd не найден — настройки применятся при следующем запуске');
}

function main(array $args)
{
    global $DRY_RUN, $COMMITTED, $CHANGES, $BACKUP_DIR;
    parse_args($args);
    load_params();
    preflight();
    if ($DRY_RUN) {
        log_info('Режим --dry-run: изменения не вносятся');
    }

    lockout_guard();
    ensure_host_keys();
    report_params();
    ensure_user();
    ensure_ssh_dir();
    install_pubkeys();
    apply_sshd_config();
    validate_and_verify();
    $COMMITTED = true;
    reload_sshd();

    echo "\n";
    if ($DRY_RUN) {
        log_info("Будет изменено: $CHANGES");
    } elseif ($CHANGES) {
        log_info("Готово. Изменений: $CHANGES");
        if ($BACKUP_DIR !== '') {
            log_info("Резервная копия: $BACKUP_DIR");
        }
    } else {
        log_info('Готово. Система уже в нужном состоянии, изменений нет');
    }
}

set_error_handler(function ($no, $str, $file, $line) {
    if (!(error_reporting() & $no)) {
        return false;
    }
    throw new ErrorException($str, 0, $no, $file, $line);
});

try {
    main(array_slice($argv, 1));
} catch (Throwable $e) {
    on_error($e);
}
