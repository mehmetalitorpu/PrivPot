from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import re
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/data/siem.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

# Database Models
class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer)
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    command = db.Column(db.Text)
    session_id = db.Column(db.String(100))
    error = db.Column(db.Text)
    raw_log = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_entry_id = db.Column(db.Integer, db.ForeignKey('log_entry.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    log_entry = db.relationship('LogEntry', backref=db.backref('alerts', lazy=True))
    rule = db.relationship('Rule', backref=db.backref('alerts', lazy=True))

# Log File Watcher
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.last_position = 0
        if os.path.exists(log_file_path):
            self.last_position = os.path.getsize(log_file_path)

    def process_existing_logs(self):
        """Process all existing logs in the file"""
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                print(f"Found {len(lines)} existing log lines to process")
                
                for line in lines:
                    if line.strip():
                        self.parse_and_store_log(line.strip())
                
                self.last_position = f.tell()
                print("Finished processing existing logs")
        except Exception as e:
            print(f"Error processing existing logs: {e}")

    def on_modified(self, event):
        if event.src_path == self.log_file_path:
            print(f"Log file modified: {event.src_path}")
            self.process_new_logs()

    def process_new_logs(self):
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                if new_lines:
                    print(f"Processing {len(new_lines)} new log lines...")
                    for line in new_lines:
                        if line.strip():
                            self.parse_and_store_log(line.strip())
                    print("New logs processed successfully!")
        except Exception as e:
            print(f"Error processing log file: {e}")

    def parse_and_store_log(self, log_line):
        try:
            # Try to parse as JSON first (jsonl format)
            if log_line.startswith('{'):
                log_data = json.loads(log_line)
                self.store_json_log(log_data)
            else:
                # Parse as text log format
                self.store_text_log(log_line)
        except Exception as e:
            print(f"Error parsing log line: {e}")

    def store_json_log(self, log_data):
        log_entry = LogEntry(
            timestamp=datetime.fromtimestamp(log_data.get('ts', time.time())),
            event_type=log_data.get('evt', 'unknown'),
            source_ip=log_data.get('src_ip', ''),
            source_port=log_data.get('src_port'),
            username=log_data.get('username'),
            password=log_data.get('password'),
            command=log_data.get('cmd'),
            session_id=log_data.get('session_id'),
            error=log_data.get('error'),
            raw_log=json.dumps(log_data)
        )
        
        db.session.add(log_entry)
        db.session.commit()
        
        # Check against rules
        self.check_rules(log_entry)

    def store_text_log(self, log_line):
        # Parse text format: "2025-09-05 12:13:15,547 CONN conn_open 172.18.0.1:47520 sid=aa5571e145abd084dce1ea15fb51abc0"
        parts = log_line.split()
        if len(parts) >= 4:
            timestamp_str = f"{parts[0]} {parts[1]}"
            event_type = parts[2]
            action = parts[3]
            
            # Extract IP and port
            source_ip = ""
            source_port = None
            username = None
            password = None
            command = None
            session_id = None
            error = None
            
            for part in parts[4:]:
                if ':' in part and '.' in part:
                    if ':' in part.split(':')[0]:
                        source_ip = part.split(':')[0]
                        source_port = int(part.split(':')[1])
                elif part.startswith('user='):
                    username = part.split('=')[1]
                elif part.startswith('pass='):
                    password = part.split('=')[1]
                elif part.startswith('cmd='):
                    command = part.split('=')[1]
                elif part.startswith('sid='):
                    session_id = part.split('=')[1]
                elif part.startswith('error='):
                    error = part.split('=')[1]
            
            log_entry = LogEntry(
                timestamp=datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f'),
                event_type=event_type,
                source_ip=source_ip,
                source_port=source_port,
                username=username,
                password=password,
                command=command,
                session_id=session_id,
                error=error,
                raw_log=log_line
            )
            
            db.session.add(log_entry)
            db.session.commit()
            
            # Check against rules
            self.check_rules(log_entry)

    def check_rules(self, log_entry):
        rules = Rule.query.filter_by(is_active=True).all()
        
        for rule in rules:
            try:
                # Check if pattern matches in command, username, or raw log
                search_text = ""
                if log_entry.command:
                    search_text += log_entry.command + " "
                if log_entry.username:
                    search_text += log_entry.username + " "
                search_text += log_entry.raw_log
                
                if re.search(rule.pattern, search_text, re.IGNORECASE):
                    alert = Alert(
                        log_entry_id=log_entry.id,
                        rule_id=rule.id,
                        severity=rule.severity
                    )
                    db.session.add(alert)
                    db.session.commit()
                    print(f"Alert triggered: {rule.name} for log entry {log_entry.id}")
            except Exception as e:
                print(f"Error checking rule {rule.name}: {e}")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    # Process new logs before returning data
    process_new_logs_from_file()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity = request.args.get('severity')
    source_ip = request.args.get('source_ip')
    event_type = request.args.get('event_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = LogEntry.query
    
    if severity:
        query = query.join(Alert).filter(Alert.severity == severity)
    
    if source_ip:
        query = query.filter(LogEntry.source_ip.like(f'%{source_ip}%'))
    
    if event_type:
        query = query.filter(LogEntry.event_type == event_type)
    
    if start_date:
        start_dt = datetime.fromisoformat(start_date)
        query = query.filter(LogEntry.timestamp >= start_dt)
    
    if end_date:
        end_dt = datetime.fromisoformat(end_date)
        query = query.filter(LogEntry.timestamp <= end_dt)
    
    logs = query.order_by(LogEntry.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'logs': [{
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'event_type': log.event_type,
            'source_ip': log.source_ip,
            'source_port': log.source_port,
            'username': log.username,
            'command': log.command,
            'session_id': log.session_id,
            'error': log.error,
            'alerts': [{'severity': alert.severity, 'rule_name': alert.rule.name} for alert in log.alerts]
        } for log in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'current_page': page
    })

@app.route('/api/rules', methods=['GET', 'POST'])
def manage_rules():
    if request.method == 'GET':
        rules = Rule.query.all()
        return jsonify([{
            'id': rule.id,
            'name': rule.name,
            'pattern': rule.pattern,
            'severity': rule.severity,
            'description': rule.description,
            'is_active': rule.is_active,
            'created_at': rule.created_at.isoformat()
        } for rule in rules])
    
    elif request.method == 'POST':
        data = request.get_json()
        rule = Rule(
            name=data['name'],
            pattern=data['pattern'],
            severity=data['severity'],
            description=data.get('description', ''),
            is_active=data.get('is_active', True)
        )
        db.session.add(rule)
        db.session.commit()
        return jsonify({'id': rule.id, 'message': 'Rule created successfully'})

@app.route('/api/rules/<int:rule_id>', methods=['PUT', 'DELETE'])
def manage_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    
    if request.method == 'PUT':
        data = request.get_json()
        rule.name = data.get('name', rule.name)
        rule.pattern = data.get('pattern', rule.pattern)
        rule.severity = data.get('severity', rule.severity)
        rule.description = data.get('description', rule.description)
        rule.is_active = data.get('is_active', rule.is_active)
        db.session.commit()
        return jsonify({'message': 'Rule updated successfully'})
    
    elif request.method == 'DELETE':
        db.session.delete(rule)
        db.session.commit()
        return jsonify({'message': 'Rule deleted successfully'})

@app.route('/api/stats')
def get_stats():
    # Process new logs before returning stats
    process_new_logs_from_file()
    
    total_logs = LogEntry.query.count()
    total_alerts = Alert.query.count()
    
    # Severity breakdown
    severity_stats = db.session.query(Alert.severity, db.func.count(Alert.id)).group_by(Alert.severity).all()
    
    # Top source IPs
    top_ips = db.session.query(LogEntry.source_ip, db.func.count(LogEntry.id)).group_by(LogEntry.source_ip).order_by(db.func.count(LogEntry.id).desc()).limit(10).all()
    
    # Recent activity (last 24 hours)
    recent_cutoff = datetime.utcnow() - timedelta(hours=24)
    recent_logs = LogEntry.query.filter(LogEntry.timestamp >= recent_cutoff).count()
    recent_alerts = Alert.query.join(LogEntry).filter(LogEntry.timestamp >= recent_cutoff).count()
    
    return jsonify({
        'total_logs': total_logs,
        'total_alerts': total_alerts,
        'recent_logs': recent_logs,
        'recent_alerts': recent_alerts,
        'severity_breakdown': dict(severity_stats),
        'top_source_ips': [{'ip': ip, 'count': count} for ip, count in top_ips]
    })

def process_new_logs_from_file():
    """Process new logs from file and add to database"""
    try:
        # Try JSON format first, then text format
        json_log_path = '/var/log/ssh-honeypot/ssh_honeypot.jsonl'
        text_log_path = '/var/log/ssh-honeypot/ssh_honeypot.log'
        
        # Process JSON logs if exists
        if os.path.exists(json_log_path):
            with open(json_log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                for line in lines:
                    if line.strip():
                        try:
                            # Check if log already exists
                            existing = LogEntry.query.filter_by(raw_log=line.strip()).first()
                            if not existing:
                                # Parse JSON log
                                if line.strip().startswith('{'):
                                    log_data = json.loads(line.strip())
                                    log_entry = LogEntry(
                                        timestamp=datetime.fromtimestamp(log_data.get('ts', 0)),
                                        event_type=log_data.get('evt', 'unknown'),
                                        source_ip=log_data.get('src_ip', ''),
                                        source_port=log_data.get('src_port'),
                                        username=log_data.get('username'),
                                        password=log_data.get('password'),
                                        command=log_data.get('cmd'),
                                        session_id=log_data.get('session_id'),
                                        error=log_data.get('error'),
                                        raw_log=line.strip()
                                    )
                                    db.session.add(log_entry)
                                    
                                    # Check against rules
                                    check_rules_for_log(log_entry)
                                    
                                    print(f"Added JSON log: {log_data.get('evt')} from {log_data.get('src_ip')}")
                        except Exception as e:
                            print(f"Error processing JSON log line: {e}")
        
        # Process text logs if exists
        if os.path.exists(text_log_path):
            with open(text_log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                for line in lines:
                    if line.strip():
                        try:
                            # Check if log already exists
                            existing = LogEntry.query.filter_by(raw_log=line.strip()).first()
                            if not existing:
                                # Parse text log format
                                parts = line.strip().split()
                                if len(parts) >= 4:
                                    timestamp_str = f"{parts[0]} {parts[1]}"
                                    event_type = parts[2]
                                    action = parts[3]
                                    
                                    # Extract IP and port
                                    source_ip = ""
                                    source_port = None
                                    username = None
                                    password = None
                                    command = None
                                    session_id = None
                                    error = None
                                    
                                    for part in parts[4:]:
                                        if ':' in part and '.' in part:
                                            if ':' in part.split(':')[0]:
                                                source_ip = part.split(':')[0]
                                                source_port = int(part.split(':')[1])
                                        elif part.startswith('user='):
                                            username = part.split('=')[1]
                                        elif part.startswith('pass='):
                                            password = part.split('=')[1]
                                        elif part.startswith('cmd='):
                                            command = part.split('=')[1]
                                        elif part.startswith('sid='):
                                            session_id = part.split('=')[1]
                                        elif part.startswith('error='):
                                            error = part.split('=')[1]
                                    
                                    log_entry = LogEntry(
                                        timestamp=datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f'),
                                        event_type=event_type,
                                        source_ip=source_ip,
                                        source_port=source_port,
                                        username=username,
                                        password=password,
                                        command=command,
                                        session_id=session_id,
                                        error=error,
                                        raw_log=line.strip()
                                    )
                                    db.session.add(log_entry)
                                    
                                    # Check against rules
                                    check_rules_for_log(log_entry)
                                    
                                    print(f"Added text log: {event_type} from {source_ip}")
                        except Exception as e:
                            print(f"Error processing text log line: {e}")
                
                db.session.commit()
    except Exception as e:
        print(f"Error processing log file: {e}")

def check_rules_for_log(log_entry):
    """Check log entry against rules and create alerts"""
    rules = Rule.query.filter_by(is_active=True).all()
    
    for rule in rules:
        try:
            search_text = ""
            if log_entry.command:
                search_text += log_entry.command + " "
            if log_entry.username:
                search_text += log_entry.username + " "
            search_text += log_entry.raw_log
            
            if re.search(rule.pattern, search_text, re.IGNORECASE):
                alert = Alert(
                    log_entry_id=log_entry.id,
                    rule_id=rule.id,
                    severity=rule.severity
                )
                db.session.add(alert)
                print(f"Alert created: {rule.name} for log {log_entry.id}")
        except Exception as e:
            print(f"Error checking rule {rule.name}: {e}")

def start_log_polling():
    """Start polling for new logs every 2 seconds"""
    def poll_logs():
        log_file_path = '/var/log/ssh-honeypot/ssh_honeypot.jsonl'
        if not os.path.exists(log_file_path):
            log_file_path = '/var/log/ssh-honeypot/ssh_honeypot.log'
        
        if os.path.exists(log_file_path):
            print(f"Found log file: {log_file_path}")
            event_handler = LogFileHandler(log_file_path)
            
            # Process existing logs first
            print("Processing existing logs...")
            event_handler.process_existing_logs()
            
            # Start polling for new logs
            print("Starting log polling every 2 seconds...")
            while True:
                try:
                    event_handler.process_new_logs()
                    time.sleep(2)
                except Exception as e:
                    print(f"Error in log polling: {e}")
                    time.sleep(5)
        else:
            print(f"Log file not found: {log_file_path}")
    
    # Start polling in background thread
    poll_thread = threading.Thread(target=poll_logs)
    poll_thread.daemon = True
    poll_thread.start()
    print("Log polling thread started")
    return poll_thread

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create default rules
        if Rule.query.count() == 0:
            default_rules = [
                Rule(name="Command Injection - whoami", pattern=r'\bwhoami\b', severity="High", description="Attempt to execute whoami command"),
                Rule(name="Command Injection - cat passwd", pattern=r'cat\s+/etc/passwd', severity="Critical", description="Attempt to read password file"),
                Rule(name="Command Injection - ls", pattern=r'\bls\b', severity="Medium", description="Attempt to list directory contents"),
                Rule(name="Command Injection - pwd", pattern=r'\bpwd\b', severity="Low", description="Attempt to get current directory"),
                Rule(name="Suspicious Username", pattern=r'(admin|root|administrator|test|guest)', severity="Medium", description="Suspicious username detected"),
                Rule(name="Password File Access", pattern=r'(passwd|shadow|group)', severity="Critical", description="Attempt to access system files"),
                Rule(name="Network Commands", pattern=r'(netstat|ss|ifconfig|ip\s+addr)', severity="High", description="Network reconnaissance commands"),
                Rule(name="System Information", pattern=r'(uname|hostname|id|whoami)', severity="Medium", description="System information gathering"),
            ]
            
            for rule in default_rules:
                db.session.add(rule)
            db.session.commit()
            print("Created default rules")
    
    # Start log polling
    poll_thread = start_log_polling()
    
    print("Starting Flask application...")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
