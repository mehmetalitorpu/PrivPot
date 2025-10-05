"""
Log Analyzer - Honeypot loglarını analiz eder ve raporlar
"""
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, Counter
import re

class LogAnalyzer:
    def __init__(self, log_dir: str = "./logs"):
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / "ssh_honeypot.jsonl"
        
    def analyze_logs(self, hours: int = 24) -> Dict:
        """Logları analiz et ve rapor oluştur"""
        if not self.log_file.exists():
            return {"error": "Log dosyası bulunamadı"}
        
        # Belirtilen saat içindeki logları oku
        cutoff_time = datetime.now() - timedelta(hours=hours)
        logs = self._read_logs_since(cutoff_time)
        
        if not logs:
            return {"error": f"Son {hours} saatte log bulunamadı"}
        
        # Analiz yap
        analysis = {
            "summary": self._analyze_summary(logs),
            "connections": self._analyze_connections(logs),
            "authentication": self._analyze_authentication(logs),
            "commands": self._analyze_commands(logs),
            "threats": self._analyze_threats(logs),
            "geography": self._analyze_geography(logs),
            "timeline": self._analyze_timeline(logs),
            "recommendations": self._generate_recommendations(logs)
        }
        
        return analysis
    
    def _read_logs_since(self, cutoff_time: datetime) -> List[Dict]:
        """Belirtilen zamandan sonraki logları oku"""
        logs = []
        
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        log_time = datetime.fromisoformat(log_entry.get('timestamp', ''))
                        
                        if log_time >= cutoff_time:
                            logs.append(log_entry)
                    except (json.JSONDecodeError, ValueError):
                        continue
        except FileNotFoundError:
            pass
        
        return logs
    
    def _analyze_summary(self, logs: List[Dict]) -> Dict:
        """Genel özet analizi"""
        total_events = len(logs)
        unique_ips = len(set(log.get('src_ip') for log in logs if log.get('src_ip')))
        unique_users = len(set(log.get('username') for log in logs if log.get('username')))
        
        # Event türleri
        event_types = Counter(log.get('event_type') for log in logs)
        
        return {
            "total_events": total_events,
            "unique_ips": unique_ips,
            "unique_users": unique_users,
            "event_types": dict(event_types),
            "time_range": {
                "start": min(log.get('timestamp', '') for log in logs),
                "end": max(log.get('timestamp', '') for log in logs)
            }
        }
    
    def _analyze_connections(self, logs: List[Dict]) -> Dict:
        """Bağlantı analizi"""
        connection_logs = [log for log in logs if log.get('event_type') in ['conn_open', 'conn_close']]
        
        # IP bazında bağlantı sayıları
        ip_connections = Counter(log.get('src_ip') for log in connection_logs if log.get('src_ip'))
        
        # Bağlantı süreleri (basit hesaplama)
        connection_times = {}
        for log in connection_logs:
            ip = log.get('src_ip')
            if not ip:
                continue
                
            if log.get('event_type') == 'conn_open':
                connection_times[ip] = log.get('timestamp')
            elif log.get('event_type') == 'conn_close' and ip in connection_times:
                # Bağlantı süresini hesapla (basit)
                del connection_times[ip]
        
        return {
            "total_connections": len([log for log in connection_logs if log.get('event_type') == 'conn_open']),
            "active_connections": len(connection_times),
            "top_ips": dict(ip_connections.most_common(10)),
            "connection_attempts_per_ip": dict(ip_connections)
        }
    
    def _analyze_authentication(self, logs: List[Dict]) -> Dict:
        """Kimlik doğrulama analizi"""
        auth_logs = [log for log in logs if log.get('event_type') == 'auth']
        
        if not auth_logs:
            return {"total_attempts": 0}
        
        # Kullanıcı adı analizi
        usernames = [log.get('username') for log in auth_logs if log.get('username')]
        username_counts = Counter(usernames)
        
        # Şifre analizi (maskelenmiş)
        passwords = [log.get('password') for log in auth_logs if log.get('password')]
        password_counts = Counter(passwords)
        
        # IP bazında auth denemeleri
        auth_by_ip = defaultdict(int)
        for log in auth_logs:
            ip = log.get('src_ip')
            if ip:
                auth_by_ip[ip] += 1
        
        return {
            "total_attempts": len(auth_logs),
            "unique_usernames": len(set(usernames)),
            "unique_passwords": len(set(passwords)),
            "top_usernames": dict(username_counts.most_common(10)),
            "top_passwords": dict(password_counts.most_common(10)),
            "auth_attempts_by_ip": dict(auth_by_ip)
        }
    
    def _analyze_commands(self, logs: List[Dict]) -> Dict:
        """Komut analizi"""
        command_logs = [log for log in logs if log.get('event_type') == 'cmd']
        
        if not command_logs:
            return {"total_commands": 0}
        
        # Komut analizi
        commands = [log.get('cmd') for log in command_logs if log.get('cmd')]
        command_counts = Counter(commands)
        
        # Tehlikeli komutlar
        dangerous_commands = [
            'rm -rf', 'chmod 777', 'wget', 'curl', 'nc', 'netcat',
            'python', 'perl', 'bash', 'sh', 'cat /etc/passwd',
            'cat /etc/shadow', 'su', 'sudo', 'passwd', 'useradd',
            'usermod', 'groupadd', 'chown', 'chmod', 'iptables',
            'ufw', 'systemctl', 'service', 'crontab', 'at',
            'nohup', 'screen', 'tmux', 'ssh', 'scp', 'rsync'
        ]
        
        dangerous_found = []
        for cmd in commands:
            for dangerous in dangerous_commands:
                if dangerous.lower() in cmd.lower():
                    dangerous_found.append(cmd)
                    break
        
        # Komut kategorileri
        categories = {
            'file_operations': ['ls', 'cat', 'cd', 'pwd', 'find', 'grep', 'head', 'tail'],
            'system_info': ['whoami', 'id', 'uname', 'hostname', 'ps', 'top', 'df', 'free', 'uptime'],
            'network': ['netstat', 'ss', 'ifconfig', 'ip', 'ping', 'traceroute', 'nmap'],
            'dangerous': dangerous_commands
        }
        
        categorized_commands = defaultdict(int)
        for cmd in commands:
            for category, keywords in categories.items():
                for keyword in keywords:
                    if keyword in cmd.lower():
                        categorized_commands[category] += 1
                        break
        
        return {
            "total_commands": len(command_logs),
            "unique_commands": len(set(commands)),
            "top_commands": dict(command_counts.most_common(20)),
            "dangerous_commands": dangerous_found,
            "categorized_commands": dict(categorized_commands),
            "commands_by_ip": self._group_commands_by_ip(command_logs)
        }
    
    def _group_commands_by_ip(self, command_logs: List[Dict]) -> Dict:
        """Komutları IP'ye göre grupla"""
        commands_by_ip = defaultdict(list)
        for log in command_logs:
            ip = log.get('src_ip')
            cmd = log.get('cmd')
            if ip and cmd:
                commands_by_ip[ip].append(cmd)
        return dict(commands_by_ip)
    
    def _analyze_threats(self, logs: List[Dict]) -> Dict:
        """Tehdit analizi"""
        threat_indicators = {
            'brute_force': self._detect_brute_force(logs),
            'suspicious_commands': self._detect_suspicious_commands(logs),
            'rapid_connections': self._detect_rapid_connections(logs),
            'privilege_escalation': self._detect_privilege_escalation(logs)
        }
        
        return threat_indicators
    
    def _detect_brute_force(self, logs: List[Dict]) -> List[Dict]:
        """Brute force saldırılarını tespit et"""
        auth_logs = [log for log in logs if log.get('event_type') == 'auth']
        
        # IP bazında auth deneme sayıları
        ip_auth_counts = defaultdict(int)
        for log in auth_logs:
            ip = log.get('src_ip')
            if ip:
                ip_auth_counts[ip] += 1
        
        # 10'dan fazla deneme yapan IP'ler
        brute_force_ips = [
            {"ip": ip, "attempts": count}
            for ip, count in ip_auth_counts.items()
            if count >= 10
        ]
        
        return brute_force_ips
    
    def _detect_suspicious_commands(self, logs: List[Dict]) -> List[Dict]:
        """Şüpheli komutları tespit et"""
        command_logs = [log for log in logs if log.get('event_type') == 'cmd']
        
        suspicious_patterns = [
            r'rm\s+-rf\s+/',
            r'chmod\s+777',
            r'wget\s+http',
            r'curl\s+http',
            r'nc\s+-l',
            r'python\s+-c',
            r'bash\s+-i',
            r'cat\s+/etc/(passwd|shadow)',
            r'su\s+root',
            r'sudo\s+',
            r'passwd\s+',
            r'useradd\s+',
            r'iptables\s+',
            r'systemctl\s+',
            r'crontab\s+',
            r'nohup\s+',
            r'ssh\s+',
            r'scp\s+',
            r'rsync\s+'
        ]
        
        suspicious_commands = []
        for log in command_logs:
            cmd = log.get('cmd', '')
            for pattern in suspicious_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    suspicious_commands.append({
                        "ip": log.get('src_ip'),
                        "username": log.get('username'),
                        "command": cmd,
                        "timestamp": log.get('timestamp'),
                        "pattern": pattern
                    })
                    break
        
        return suspicious_commands
    
    def _detect_rapid_connections(self, logs: List[Dict]) -> List[Dict]:
        """Hızlı bağlantı denemelerini tespit et"""
        connection_logs = [log for log in logs if log.get('event_type') == 'conn_open']
        
        # IP bazında bağlantı zamanları
        ip_connection_times = defaultdict(list)
        for log in connection_logs:
            ip = log.get('src_ip')
            timestamp = log.get('timestamp')
            if ip and timestamp:
                ip_connection_times[ip].append(timestamp)
        
        rapid_connections = []
        for ip, times in ip_connection_times.items():
            if len(times) >= 5:  # 5 veya daha fazla bağlantı
                rapid_connections.append({
                    "ip": ip,
                    "connection_count": len(times),
                    "first_connection": min(times),
                    "last_connection": max(times)
                })
        
        return rapid_connections
    
    def _detect_privilege_escalation(self, logs: List[Dict]) -> List[Dict]:
        """Privilege escalation denemelerini tespit et"""
        command_logs = [log for log in logs if log.get('event_type') == 'cmd']
        
        privilege_commands = [
            'su', 'sudo', 'passwd', 'useradd', 'usermod', 'groupadd',
            'chown', 'chmod', 'visudo', 'crontab', 'at', 'systemctl'
        ]
        
        privilege_attempts = []
        for log in command_logs:
            cmd = log.get('cmd', '')
            for priv_cmd in privilege_commands:
                if cmd.startswith(priv_cmd):
                    privilege_attempts.append({
                        "ip": log.get('src_ip'),
                        "username": log.get('username'),
                        "command": cmd,
                        "timestamp": log.get('timestamp')
                    })
                    break
        
        return privilege_attempts
    
    def _analyze_geography(self, logs: List[Dict]) -> Dict:
        """Coğrafi analiz (basit IP analizi)"""
        ips = [log.get('src_ip') for log in logs if log.get('src_ip')]
        unique_ips = list(set(ips))
        
        # Basit IP sınıflandırması
        ip_categories = {
            'private': [],
            'public': [],
            'localhost': []
        }
        
        for ip in unique_ips:
            if ip.startswith('127.') or ip == '::1':
                ip_categories['localhost'].append(ip)
            elif ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                ip_categories['private'].append(ip)
            else:
                ip_categories['public'].append(ip)
        
        return {
            "total_unique_ips": len(unique_ips),
            "ip_categories": {k: len(v) for k, v in ip_categories.items()},
            "top_ips": dict(Counter(ips).most_common(10))
        }
    
    def _analyze_timeline(self, logs: List[Dict]) -> Dict:
        """Zaman çizelgesi analizi"""
        # Saatlik dağılım
        hourly_counts = defaultdict(int)
        for log in logs:
            timestamp = log.get('timestamp')
            if timestamp:
                try:
                    hour = datetime.fromisoformat(timestamp).hour
                    hourly_counts[hour] += 1
                except ValueError:
                    continue
        
        return {
            "hourly_distribution": dict(hourly_counts),
            "peak_hour": max(hourly_counts.items(), key=lambda x: x[1])[0] if hourly_counts else None
        }
    
    def _generate_recommendations(self, logs: List[Dict]) -> List[str]:
        """Öneriler oluştur"""
        recommendations = []
        
        # Brute force tespiti
        brute_force_ips = self._detect_brute_force(logs)
        if brute_force_ips:
            recommendations.append(f"[ALERT] {len(brute_force_ips)} IP adresinden brute force saldırısı tespit edildi. Bu IP'leri firewall'da engelleyin.")
        
        # Şüpheli komutlar
        suspicious_commands = self._detect_suspicious_commands(logs)
        if suspicious_commands:
            recommendations.append(f"[WARNING] {len(suspicious_commands)} şüpheli komut tespit edildi. Bu komutları çalıştıran IP'leri izleyin.")
        
        # Hızlı bağlantılar
        rapid_connections = self._detect_rapid_connections(logs)
        if rapid_connections:
            recommendations.append(f"[WARNING] {len(rapid_connections)} IP'den hızlı bağlantı denemesi tespit edildi. Rate limiting uygulayın.")
        
        # Genel öneriler
        if not recommendations:
            recommendations.append("[SUCCESS] Şu ana kadar ciddi bir tehdit tespit edilmedi.")
        
        recommendations.extend([
            "[INFO] Logları düzenli olarak analiz edin",
            "[SECURITY] Güçlü şifreler kullanın ve 2FA aktifleştirin",
            "[SECURITY] Fail2ban veya benzeri araçları kullanın",
            "[MONITOR] Anormal aktiviteleri izleyin"
        ])
        
        return recommendations
    
    def generate_report(self, hours: int = 24) -> str:
        """Detaylı rapor oluştur"""
        analysis = self.analyze_logs(hours)
        
        if "error" in analysis:
            return f"[ERROR] Hata: {analysis['error']}"
        
        report = f"""
[ANALYSIS] SSH HONEYPOT ANALİZ RAPORU
{'='*50}

[SUMMARY] GENEL ÖZET
{'─'*20}
• Toplam Olay: {analysis['summary']['total_events']}
• Benzersiz IP: {analysis['summary']['unique_ips']}
• Benzersiz Kullanıcı: {analysis['summary']['unique_users']}
• Zaman Aralığı: {analysis['summary']['time_range']['start']} - {analysis['summary']['time_range']['end']}

[AUTH] KİMLİK DOĞRULAMA
{'─'*20}
• Toplam Deneme: {analysis['authentication']['total_attempts']}
• En Çok Denenen Kullanıcılar: {list(analysis['authentication']['top_usernames'].keys())[:5]}
• En Çok Denenen Şifreler: {list(analysis['authentication']['top_passwords'].keys())[:5]}

[COMMANDS] KOMUT ANALİZİ
{'─'*20}
• Toplam Komut: {analysis['commands']['total_commands']}
• En Çok Kullanılan Komutlar: {list(analysis['commands']['top_commands'].keys())[:10]}
• Tehlikeli Komutlar: {len(analysis['commands']['dangerous_commands'])}

[THREATS] TEHDİT ANALİZİ
{'─'*20}
• Brute Force Saldırıları: {len(analysis['threats']['brute_force'])}
• Şüpheli Komutlar: {len(analysis['threats']['suspicious_commands'])}
• Hızlı Bağlantılar: {len(analysis['threats']['rapid_connections'])}
• Privilege Escalation: {len(analysis['threats']['privilege_escalation'])}

[GEOGRAPHY] COĞRAFİ ANALİZ
{'─'*20}
• Toplam Benzersiz IP: {analysis['geography']['total_unique_ips']}
• Yerel Ağ: {analysis['geography']['ip_categories']['private']}
• Genel Ağ: {analysis['geography']['ip_categories']['public']}

[RECOMMENDATIONS] ÖNERİLER
{'─'*20}
"""
        
        for i, rec in enumerate(analysis['recommendations'], 1):
            report += f"{i}. {rec}\n"
        
        return report
    
    def export_to_json(self, hours: int = 24, output_file: str = None) -> str:
        """Analizi JSON olarak dışa aktar"""
        analysis = self.analyze_logs(hours)
        
        if not output_file:
            output_file = f"honeypot_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = self.log_dir / output_file
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
