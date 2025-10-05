"""
System Cloner - Gerçek sistem dosyalarını klonlar ve honeypot için kullanır
"""
import os
import shutil
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class SystemCloner:
    def __init__(self, clone_dir: str = "./cloned_system"):
        self.clone_dir = Path(clone_dir)
        self.cloned_files = {}
        self.system_info = {}
        
    def clone_system(self) -> bool:
        """Ana sistem klonlama fonksiyonu"""
        try:
            print("[INFO] Sistem klonlanıyor...")
            
            # Clone dizinini oluştur
            self.clone_dir.mkdir(exist_ok=True)
            
            # Sistem bilgilerini topla
            self._collect_system_info()
            
            # Önemli dosyaları klonla
            self._clone_important_files()
            
            # Dosya sistemi yapısını oluştur
            self._create_filesystem_structure()
            
            # Process bilgilerini simüle et
            self._simulate_processes()
            
            # Network bilgilerini simüle et
            self._simulate_network()
            
            print(f"[SUCCESS] Sistem başarıyla klonlandı: {self.clone_dir}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Klonlama hatası: {e}")
            return False
    
    def _collect_system_info(self):
        """Sistem bilgilerini topla"""
        try:
            # Hostname
            self.system_info['hostname'] = os.uname().nodename
            
            # OS bilgisi
            self.system_info['os'] = os.uname().sysname
            self.system_info['release'] = os.uname().release
            self.system_info['version'] = os.uname().version
            self.system_info['machine'] = os.uname().machine
            
            # Uptime simülasyonu
            self.system_info['uptime'] = "15 days, 3 hours, 42 minutes"
            
            # Memory bilgisi
            self.system_info['memory'] = "8GB RAM, 2GB swap"
            
            # CPU bilgisi
            self.system_info['cpu'] = "Intel Core i7-8700K @ 3.70GHz (6 cores)"
            
        except Exception as e:
            logger.warning(f"Sistem bilgisi toplanamadı: {e}")
            # Varsayılan değerler
            self.system_info = {
                'hostname': 'prod-server-01',
                'os': 'Linux',
                'release': '5.15.0-91-generic',
                'version': '#102-Ubuntu SMP Fri Nov 10 16:16:57 UTC 2023',
                'machine': 'x86_64',
                'uptime': '15 days, 3 hours, 42 minutes',
                'memory': '8GB RAM, 2GB swap',
                'cpu': 'Intel Core i7-8700K @ 3.70GHz (6 cores)'
            }
    
    def _clone_important_files(self):
        """Önemli sistem dosyalarını klonla"""
        important_files = [
            '/etc/passwd',
            '/etc/group',
            '/etc/hosts',
            '/etc/hostname',
            '/etc/os-release',
            '/proc/version',
            '/proc/cpuinfo',
            '/proc/meminfo',
            '/proc/loadavg',
            '/proc/uptime'
        ]
        
        for file_path in important_files:
            try:
                if os.path.exists(file_path):
                    # Dosyayı oku
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Clone dizinine kaydet
                    relative_path = file_path.lstrip('/')
                    clone_path = self.clone_dir / relative_path
                    clone_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(clone_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    self.cloned_files[file_path] = str(clone_path)
                    print(f"[INFO] Klonlandı: {file_path}")
                    
            except Exception as e:
                logger.warning(f"Dosya klonlanamadı {file_path}: {e}")
    
    def _create_filesystem_structure(self):
        """Gerçekçi dosya sistemi yapısı oluştur"""
        # Ana dizinler
        dirs = [
            'etc', 'home', 'var', 'usr', 'bin', 'sbin', 'opt', 'tmp',
            'etc/ssh', 'etc/network', 'etc/systemd', 'etc/nginx',
            'home/user', 'home/admin', 'home/backup',
            'var/log', 'var/www', 'var/mail', 'var/spool',
            'usr/bin', 'usr/sbin', 'usr/local', 'usr/share',
            'opt/apps', 'opt/backup', 'opt/configs'
        ]
        
        for dir_path in dirs:
            (self.clone_dir / dir_path).mkdir(parents=True, exist_ok=True)
        
        # Önemli dosyalar oluştur
        self._create_important_files()
        
        # Bait dosyalar oluştur
        self._create_bait_files()
    
    def _create_important_files(self):
        """Önemli sistem dosyalarını oluştur"""
        
        # /etc/passwd
        passwd_content = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:irc:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd/timesync:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
user:x:1001:1001:Regular User:/home/user:/bin/bash
admin:x:1002:1002:Administrator:/home/admin:/bin/bash
backup:x:1003:1003:Backup User:/home/backup:/bin/bash
"""
        
        with open(self.clone_dir / 'etc' / 'passwd', 'w') as f:
            f.write(passwd_content)
        
        # /etc/hosts
        hosts_content = """127.0.0.1	localhost
127.0.1.1	prod-server-01

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
"""
        
        with open(self.clone_dir / 'etc' / 'hosts', 'w') as f:
            f.write(hosts_content)
        
        # /etc/hostname
        with open(self.clone_dir / 'etc' / 'hostname', 'w') as f:
            f.write(self.system_info['hostname'])
        
        # /proc/version
        version_content = f"""Linux version {self.system_info['release']} (buildd@lcy02-amd64-023) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #102-Ubuntu SMP Fri Nov 10 16:16:57 UTC 2023
"""
        
        with open(self.clone_dir / 'proc' / 'version', 'w') as f:
            f.write(version_content)
    
    def _create_bait_files(self):
        """Saldırganları çekmek için bait dosyalar oluştur"""
        bait_files = {
            'home/admin/.ssh/id_rsa': """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1234567890abcdef...
-----END OPENSSH PRIVATE KEY-----""",
            
            'home/admin/.ssh/authorized_keys': """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... admin@workstation
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD8... backup@server""",
            
            'home/admin/database_backup.sql': """-- Database backup
CREATE DATABASE production_db;
USE production_db;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password_hash, email) VALUES
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@company.com'),
('user1', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user1@company.com');

CREATE TABLE sensitive_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    data TEXT,
    secret_key VARCHAR(255)
);

INSERT INTO sensitive_data (data, secret_key) VALUES
('Confidential information', 'SECRET_KEY_12345'),
('API credentials', 'API_KEY_67890');
""",
            
            'home/admin/config.yaml': """database:
  host: localhost
  port: 3306
  username: admin
  password: admin123
  database: production_db

api:
  endpoint: https://api.company.com
  key: sk-1234567890abcdef
  secret: secret123456

aws:
  access_key: AKIAIOSFODNN7EXAMPLE
  secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: us-west-2

redis:
  host: localhost
  port: 6379
  password: redis123
""",
            
            'home/admin/backup_script.sh': """#!/bin/bash
# Database backup script
mysqldump -u admin -padmin123 production_db > /home/admin/backup_$(date +%Y%m%d).sql
tar -czf /home/admin/files_backup_$(date +%Y%m%d).tar.gz /var/www/html/
rsync -avz /home/admin/backup_* backup@remote-server:/backups/
""",
            
            'var/www/html/index.php': """<?php
// Production website
$db_host = 'localhost';
$db_user = 'admin';
$db_pass = 'admin123';
$db_name = 'production_db';

$conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

echo "Welcome to Company Internal Portal";
echo "<br>Database connected successfully!";
?>
""",
            
            'etc/ssh/sshd_config': """# SSH Server Configuration
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
MaxAuthTries 3
MaxSessions 10

# Password authentication
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Logging
SyslogFacility AUTH
LogLevel INFO

# Security
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
""",
            
            'home/admin/.bash_history': """cd /var/www/html
ls -la
cat config.php
mysql -u admin -p
show databases;
use production_db;
select * from users;
exit
cd /home/admin
ls -la
cat database_backup.sql
./backup_script.sh
ssh backup@remote-server
exit
""",
            
            'var/log/auth.log': """Nov 15 10:30:15 prod-server-01 sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2
Nov 15 10:30:16 prod-server-01 sshd[1234]: pam_unix(sshd:session): session opened for user admin by (uid=0)
Nov 15 10:31:22 prod-server-01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow
Nov 15 10:31:25 prod-server-01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls -la /root
Nov 15 10:32:10 prod-server-01 sshd[1234]: pam_unix(sshd:session): session closed for user admin
Nov 15 10:35:45 prod-server-01 sshd[1235]: Failed password for root from 192.168.1.200 port 22 ssh2
Nov 15 10:35:48 prod-server-01 sshd[1235]: Failed password for root from 192.168.1.200 port 22 ssh2
Nov 15 10:35:51 prod-server-01 sshd[1235]: Failed password for root from 192.168.1.200 port 22 ssh2
Nov 15 10:35:54 prod-server-01 sshd[1235]: Connection closed by 192.168.1.200 port 22 [preauth]
"""
        }
        
        for file_path, content in bait_files.items():
            full_path = self.clone_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(full_path, 'w') as f:
                f.write(content)
            
            # Bazı dosyaları executable yap
            if file_path.endswith('.sh'):
                os.chmod(full_path, 0o755)
    
    def _simulate_processes(self):
        """Çalışan process'leri simüle et"""
        self.processes = [
            {"pid": 1, "user": "root", "cpu": 0.1, "mem": 0.5, "command": "systemd"},
            {"pid": 123, "user": "root", "cpu": 0.0, "mem": 0.2, "command": "systemd-journald"},
            {"pid": 456, "user": "root", "cpu": 0.0, "mem": 0.3, "command": "systemd-logind"},
            {"pid": 789, "user": "root", "cpu": 0.1, "mem": 0.4, "command": "systemd-resolved"},
            {"pid": 1011, "user": "root", "cpu": 0.0, "mem": 0.2, "command": "systemd-timesyncd"},
            {"pid": 1213, "user": "root", "cpu": 0.0, "mem": 0.1, "command": "systemd-udevd"},
            {"pid": 1415, "user": "root", "cpu": 0.0, "mem": 0.3, "command": "dbus-daemon"},
            {"pid": 1617, "user": "root", "cpu": 0.0, "mem": 0.2, "command": "NetworkManager"},
            {"pid": 1819, "user": "root", "cpu": 0.0, "mem": 0.4, "command": "sshd"},
            {"pid": 2021, "user": "root", "cpu": 0.0, "mem": 0.3, "command": "nginx"},
            {"pid": 2223, "user": "mysql", "cpu": 0.2, "mem": 2.1, "command": "mysqld"},
            {"pid": 2425, "user": "redis", "cpu": 0.1, "mem": 0.8, "command": "redis-server"},
            {"pid": 2627, "user": "admin", "cpu": 0.0, "mem": 0.2, "command": "bash"},
            {"pid": 2829, "user": "admin", "cpu": 0.0, "mem": 0.1, "command": "htop"},
            {"pid": 3031, "user": "root", "cpu": 0.0, "mem": 0.1, "command": "cron"},
        ]
    
    def _simulate_network(self):
        """Network interface'leri simüle et"""
        self.network_interfaces = [
            {"name": "lo", "ip": "127.0.0.1", "status": "UP"},
            {"name": "eth0", "ip": "192.168.1.100", "status": "UP"},
            {"name": "eth1", "ip": "10.0.0.50", "status": "UP"},
            {"name": "wlan0", "ip": "192.168.0.150", "status": "DOWN"},
        ]
        
        self.network_connections = [
            {"local": "192.168.1.100:22", "remote": "192.168.1.50:12345", "state": "ESTABLISHED", "service": "ssh"},
            {"local": "192.168.1.100:80", "remote": "0.0.0.0:0", "state": "LISTEN", "service": "nginx"},
            {"local": "192.168.1.100:3306", "remote": "0.0.0.0:0", "state": "LISTEN", "service": "mysql"},
            {"local": "192.168.1.100:6379", "remote": "0.0.0.0:0", "state": "LISTEN", "service": "redis"},
        ]
    
    def get_file_content(self, file_path: str) -> Optional[str]:
        """Klonlanan dosyanın içeriğini döndür"""
        try:
            # Mutlak yol kontrolü
            if file_path.startswith('/'):
                relative_path = file_path[1:]
            else:
                relative_path = file_path
            
            full_path = self.clone_dir / relative_path
            
            if full_path.exists() and full_path.is_file():
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        except Exception as e:
            logger.warning(f"Dosya okunamadı {file_path}: {e}")
        
        return None
    
    def get_system_info(self) -> Dict:
        """Sistem bilgilerini döndür"""
        return self.system_info
    
    def get_processes(self) -> List[Dict]:
        """Process listesini döndür"""
        return self.processes
    
    def get_network_info(self) -> Dict:
        """Network bilgilerini döndür"""
        return {
            'interfaces': self.network_interfaces,
            'connections': self.network_connections
        }
