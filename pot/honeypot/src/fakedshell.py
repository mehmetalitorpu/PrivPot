from __future__ import annotations

import asyncio
import os
import time
import base64
from typing import Tuple, Optional
from pathlib import Path


class FakeShell:
    def __init__(self, fake_hostname: str) -> None:
        self.fake_hostname = fake_hostname
        self.current_dir = "/home/elliot"  # Varsayılan elliot home
        self.username = "elliot"  # Varsayılan kullanıcı
        self.honeypot_fs = Path("./honeypot_elliot")  # Varsayılan elliot FS
        
    def set_user(self, username: str) -> None:
        """Kullanıcıyı ayarla ve home dizinini güncelle"""
        self.username = username
        if username == "elliot":
            self.current_dir = "/home/elliot"
            self.honeypot_fs = Path("./honeypot_elliot")
        elif username == "mrrobot":
            self.current_dir = "/home/mrrobot"
            self.honeypot_fs = Path("./honeypot_mrrobot")
        elif username == "anonymous":
            self.current_dir = "/home/anonymous"
            self.honeypot_fs = Path("./cloned_system")
        else:
            self.current_dir = f"/home/{username}"
            self.honeypot_fs = Path("./cloned_system")
    
    async def handle_command(self, line: str) -> Tuple[str, bool]:
        cmd = (line or "").strip()
        if not cmd:
            return "", False

        # Çıkış komutları
        if cmd in {"exit", "logout", "quit"}:
            return "logout\n", True

        # Temel sistem komutları
        if cmd == "whoami":
            return f"{self.username}\n", False
            
        if cmd == "id":
            uid = 1000 if self.username == "elliot" else 1001 if self.username == "mrrobot" else 1000
            return f"uid={uid}({self.username}) gid={uid}({self.username}) groups={uid}({self.username})\n", False
            
        if cmd.startswith("uname"):
            if "-a" in cmd:
                return "Linux honeypot 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux\n", False
            elif "-r" in cmd:
                return "5.4.0-42-generic\n", False
            elif "-m" in cmd:
                return "x86_64\n", False
            else:
                return "Linux\n", False
                
        if cmd == "hostname":
            return "honeypot\n", False
            
        if cmd == "pwd":
            return f"{self.current_dir}\n", False
            
        # Dosya sistemi komutları
        if cmd.startswith("ls"):
            result = await self._handle_ls(cmd)
            return result, False
            
        if cmd.startswith("cd"):
            result = await self._handle_cd(cmd)
            return result, False
            
        if cmd.startswith("cat "):
            result = await self._handle_cat(cmd)
            return result, False
            
        if cmd.startswith("sudo"):
            result = await self._handle_sudo(cmd)
            return result, False

        # Diğer tüm komutlar için command not found
        return "bash: command not found\n", False
    
    async def _handle_ls(self, cmd: str) -> str:
        """ls komutunu işle"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        
        # Honeypot FS'deki dizini kontrol et
        target_path = self.honeypot_fs / self.current_dir.lstrip("/")
        
        if target_path.exists() and target_path.is_dir():
            try:
                files = []
                for item in target_path.iterdir():
                    if item.name.startswith('.') and not ("-a" in args or "-la" in args or "-l" in args):
                        continue
                    files.append(item.name)
                
                if "-la" in args or "-l" in args:
                    # Detaylı liste
                    result = f"total {len(files)}\n"
                    for item in sorted(target_path.iterdir()):
                        if item.name.startswith('.') and not ("-a" in args or "-la" in args or "-l" in args):
                            continue
                        
                        # Dosya izinlerini simüle et
                        if item.name == "secret" and self.username == "elliot":
                            # elliot için secret dosyası okunamaz
                            permissions = "rw-------"
                            owner = "mrrobot"
                        else:
                            permissions = "rw-r--r--"
                            owner = self.username
                        
                        size = item.stat().st_size if item.is_file() else 4096
                        mtime = item.stat().st_mtime
                        mtime_str = time.strftime("%b %d %H:%M", time.localtime(mtime))
                        
                        if item.is_dir():
                            result += f"d{permissions}  2 {owner} {owner} 4096 {mtime_str} {item.name}\n"
                        else:
                            result += f"-{permissions}  1 {owner} {owner} {size:>4} {mtime_str} {item.name}\n"
                    return result
                else:
                    # Basit liste
                    return " ".join(sorted(files)) + "\n"
            except Exception as e:
                print(f"[WARNING] ls error: {e}")
        
        # Fallback: Varsayılan dizin içerikleri
        directory_contents = {
            "/home/elliot": {
                "files": ["Desktop", "Documents", "Downloads"],
                "detailed": """total 12
drwxr-xr-x  3 elliot elliot 4096 Nov 15 10:00 .
drwxr-xr-x  3 root   root   4096 Nov 15 10:00 ..
drwxr-xr-x  2 elliot elliot 4096 Nov 15 10:00 Desktop
drwxr-xr-x  2 elliot elliot 4096 Nov 15 10:00 Documents
drwxr-xr-x  2 elliot elliot 4096 Nov 15 10:00 Downloads
"""
            },
            "/home/elliot/Desktop": {
                "files": ["secret"],
                "detailed": """total 8
drwxr-xr-x  2 elliot elliot 4096 Nov 15 10:00 .
drwxr-xr-x  3 elliot elliot 4096 Nov 15 10:00 ..
-rw-------  1 mrrobot mrrobot   45 Nov 15 10:00 secret
"""
            },
            "/home/mrrobot": {
                "files": ["Desktop", "Documents", "Downloads"],
                "detailed": """total 12
drwxr-xr-x  3 mrrobot mrrobot 4096 Nov 15 10:00 .
drwxr-xr-x  3 root    root    4096 Nov 15 10:00 ..
drwxr-xr-x  2 mrrobot mrrobot 4096 Nov 15 10:00 Desktop
drwxr-xr-x  2 mrrobot mrrobot 4096 Nov 15 10:00 Documents
drwxr-xr-x  2 mrrobot mrrobot 4096 Nov 15 10:00 Downloads
"""
            },
            "/home/mrrobot/Desktop": {
                "files": ["secret"],
                "detailed": """total 8
drwxr-xr-x  2 mrrobot mrrobot 4096 Nov 15 10:00 .
drwxr-xr-x  3 mrrobot mrrobot 4096 Nov 15 10:00 ..
-rw-r--r--  1 mrrobot mrrobot   10 Nov 15 10:00 secret
"""
            }
        }
        
        current_dir = self.current_dir
        if current_dir not in directory_contents:
            if "-la" in args or "-l" in args:
                return f"total 0\ndrwxr-xr-x  2 {self.username} {self.username} 4096 Nov 15 10:00 .\ndrwxr-xr-x  3 root root 4096 Nov 15 10:00 ..\n"
            else:
                return ""
        
        content = directory_contents[current_dir]
        
        if "-la" in args or "-l" in args:
            return content["detailed"]
        else:
            return " ".join(content["files"]) + "\n"
    
    async def _handle_cd(self, cmd: str) -> str:
        """cd komutunu işle"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        target_dir = args[0] if args else f"/home/{self.username}"
        
        # Dizin değiştirme simülasyonu
        if target_dir == "/":
            self.current_dir = "/"
        elif target_dir == "..":
            if self.current_dir != "/":
                self.current_dir = str(Path(self.current_dir).parent)
        elif target_dir.startswith("/"):
            # Mutlak yol
            target_path = self.honeypot_fs / target_dir.lstrip("/")
            if target_path.exists() and target_path.is_dir():
                self.current_dir = target_dir
            else:
                return f"bash: cd: {target_dir}: No such file or directory\n"
        else:
            # Göreceli yol
            new_path = str(Path(self.current_dir) / target_dir)
            target_path = self.honeypot_fs / new_path.lstrip("/")
            if target_path.exists() and target_path.is_dir():
                self.current_dir = new_path
            else:
                return f"bash: cd: {target_dir}: No such file or directory\n"
        return ""
    
    async def _handle_cat(self, cmd: str) -> str:
        """cat komutunu işle"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        if not args:
            return "cat: missing file operand\n"
        
        filename = args[0]
        
        # Honeypot FS dosyasını kontrol et
        if not filename.startswith("/"):
            # Göreceli yol
            file_path = self.honeypot_fs / self.current_dir.lstrip("/") / filename
        else:
            # Mutlak yol
            file_path = self.honeypot_fs / filename.lstrip("/")
        
        # Özel dosya kontrolleri
        if filename == "secret" or filename.endswith("/secret"):
            if self.username == "elliot":
                return "cat: /home/elliot/Desktop/secret: Permission denied\n"
            elif self.username == "mrrobot":
                if file_path.exists() and file_path.is_file():
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            return f.read()
                    except Exception as e:
                        return f"cat: {filename}: {str(e)}\n"
                else:
                    return f"cat: {filename}: No such file or directory\n"
        
        if file_path.exists() and file_path.is_file():
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except Exception as e:
                return f"cat: {filename}: {str(e)}\n"
        
        return f"cat: {filename}: No such file or directory\n"
    
    async def _handle_sudo(self, cmd: str) -> str:
        """sudo komutunu işle"""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        
        if not args:
            return "sudo: a command is required\n"
        
        if args[0] == "-l":
            # sudo -l komutu
            if self.username == "elliot":
                return """Matching Defaults entries for elliot on honeypot:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elliot may run the following commands on honeypot:
    (root) NOPASSWD: ALL

User mrrobot may run the following commands on honeypot:
    (root) NOPASSWD: ALL
"""
            elif self.username == "mrrobot":
                return """Matching Defaults entries for mrrobot on honeypot:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrrobot may run the following commands on honeypot:
    (root) NOPASSWD: ALL
"""
            else:
                return f"User {self.username} is not in the sudoers file. This incident will be reported.\n"
        
        # Diğer sudo komutları için
        return f"sudo: {args[0]}: command not found\n"