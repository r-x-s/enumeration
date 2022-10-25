#!/bin/bash
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
BLUE="${C}[1;34m"
NC="${C}[0m"


echo_heading(){
 printf  "$BLUE**$1$NC\n"
}
echo_section (){
  printf "\n$RED**********\n$NC"
}

echo_command(){
    echo_section
    if [ ${2+x} ] #from https://stackoverflow.com/questions/3601515/how-to-check-if-a-variable-is-set-in-bash to check if 2nd argument exists
    then
      echo_heading "$2"
    fi
    printf "$GREEN$1  \n$NC"
}

echo_command "whoami" "WHOAMIIIII I WONDER"
whoami

echo_command "id"
id

echo_command "groups"
groups

echo_command "sudo -l"
sudo -l

echo_command "cat ~/.nano_history; cat ~/.atftp_history; cat ~/.mysql_history; cat ~/.php_history; cat ~/.bash_history; "
cat  cat ~/.nano_history; cat ~/.atftp_history; cat ~/.mysql_history; cat ~/.php_history; ~/.bash_history;

echo_command "cat /etc/passwd"
cat /etc/passwd

echo_command 'cat /etc/passwd 2>/dev/null | grep  "sh$"      ####users with shells'
cat /etc/passwd 2>/dev/null | grep  "sh$"


echo_command "which nc...etc" "USEFUL SOFTWARE"
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null

echo_heading "SUID binaries - remember exploits not just gtfo"
#echo_command "find / -perm -4000 -exec ls -al -print 2>/dev/null {} \;" "SUID binaries"
#find / -perm -4000 -exec ls -al -print 2>/dev/null {} \;

#rxs list of gtfobins binaries retrieved with :   var russ="";elements.forEach(function(el){russ= russ+ " " +  el.text;});console.log(russ);
#apt-get apt ar aria2c arj arp ash at atobm awk base32 base64 basenc bash bpftrace bridge bundler busctl busybox byebug c89 c99 cancel capsh cat certbot check_by_ssh check_cups check_log check_memory check_raid check_ssl_cert check_statusfile chmod chown chroot cobc column comm composer cowsay cowthink cp cpan cpio cpulimit crash crontab csh csplit csvtool cupsfilter curl cut dash date dd dialog diff dig dmesg dmsetup dnf docker dpkg dvips easy_install eb ed emacs env eqn ex exiftool expand expect facter file find finger flock fmt fold ftp gawk gcc gdb gem genisoimage ghc ghci gimp git grep gtester gzip hd head hexdump highlight hping3 iconv iftop install ionice ip irb jjs join journalctl jq jrunscript ksh ksshell latex ld.so ldconfig less loginctl logsave look ltrace lua lualatex luatex lwp-download lwp-request mail make man mawk more mount msgattrib msgcat msgconv msgfilter msgmerge msguniq mtr mv mysql nano nawk nc nice nl nmap node nohup npm nroff nsenter octave od openssl openvpn openvt paste pdb pdflatex pdftex perl pg php pic pico pip pkexec pkg pr pry psql puppet python rake readelf red redcarpet restic rev rlogin rlwrap rpm rpmquery rsync ruby run-mailcap run-parts rview rvim scp screen script sed service setarch sftp sg shuf slsh smbclient snap socat soelim sort split sqlite3 ss ssh-keygen ssh-keyscan ssh start-stop-daemon stdbuf strace strings su sysctl systemctl tac tail tar taskset tbl tclsh tcpdump tee telnet tex tftp time timedatectl timeout tmux top troff tshark ul unexpand uniq unshare update-alternatives uudecode uuencode valgrind vi view vigr vim vimdiff vipw virsh watch wc wget whois wish xargs xelatex xetex xmodmap xmore xxd xz yarn yelp yum zip zsh zsoelim zypper
echo_command "find / -perm -4000 -type f 2>/dev/null | xargs ls -lahtr | while read s; do     sname="`echo \"$s\" | awk '{print $9}'`"; ls -lah $sname; done;" "SUID binaries"
find / -perm -4000 -type f 2>/dev/null | xargs ls -lahtr | while read s; do     sname="`echo \"$s\" | awk '{print $9}'`"; ls -lah $sname; done;

echo_command "find / -writable -type d 2>/dev/null" "WRITEABLE FOLDERS"
find / -writable -type d 2>/dev/null

echo_command "find / -writable -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null" "WRITEABLE FILES"
find / -writable -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null

echo_command "(find / -type f -user root ! -perm -o=r 2>/dev/null | grep -v "\.journal" | while read f; do if [ -r "$f" ]; then ls -l "$f" 2>/dev/null | sed -${E} "s,/.*,${C}[1;31m&${C}[0m,"; fi; done) || echo_not_found
" "Files owned by root readable by me"
(find / -type f -user root ! -perm -o=r 2>/dev/null | grep -v "\.journal" | while read f; do if [ -r "$f" ]; then ls -l "$f" 2>/dev/null | sed -${E} "s,/.*,${C}[1;31m&${C}[0m,"; fi; done) || echo_not_found

echo_command "hostname"
hostname

echo_command "cat /etc/issue"
cat /etc/issue

echo_command "cat /etc/*release"
cat /etc/*release

echo_command "uname -a"
uname -a

echo_command "ps axu" "RUNNING PROCESSES"
ps axu

echo_heading "NETWORK INFO"
echo_command "ip a"
ip a

echo_command "netstat -anp"
netstat -anp

echo_command "ss -anp"
ss -anp

echo_command "ls -lah /etc/cron*"
ls -lah /etc/cron*

echo_command "cat /etc/crontab "
cat /etc/crontab 

echo_command "grep "CRON" /var/log/cron.log"
grep "CRON" /var/log/cron.log

echo_heading "WHATS INSTALLED"
echo_command "dpkg -l"
dpkg -l

echo_command "ls -alh /usr/bin/"
ls -alh /usr/bin/

echo_command "ls -alh /sbin/"
ls -alh /sbin/

echo_heading "TRY RUNNING PSPY"

echo_heading "LOOK AROUND FILESYSTEM: Backup folder? Anything on desktop/documents/www/opt/"

echo_command "mount"
mount

echo_command "cat /etc/fstab"
cat /etc/fstab

echo_command "df -lh"
df -lh

echo_command " bin/lsblk"
bin/lsblk

echo_command "ls -lah /usr/src/"
ls -lah /usr/src/

echo_command "ls -lah /usr/local/src/"
ls -lah /usr/local/src/

echo_command "ls -lah /var/"
ls -lah /var/

echo_command "ls -lah /opt/"
ls -lah /opt/

echo_command "ls -lah /var/www/"
ls -lah /var/www/

echo_command "ls -lah /home/"
ls -lah /home/

echo_command "cat /etc/ssh/sshd_config | grep AllowUsers" "if can't ssh in check for denied users"
cat /etc/ssh/sshd_config | grep AllowUsers

echo_heading "TRY RUNNING PSPY"

echo_heading "LOOK AROUND FILESYSTEM: Backup folder? Anything on desktop/documents/www/opt/"

echo_heading "Check for passwords with grep -r passw . 2>/dev/null"