#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""雅思词汇工作台 - 多用户后端（Flask + SQLite）"""
import json, os, sqlite3, time
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder=None)
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vocab.db')

@app.after_request
def add_cors(resp):
    """允许从其他页面地址调用本服务（防止用户用旧地址打开页面时接口连不上）"""
    if request.path.startswith('/api/'):
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.route('/api/<path:_sub>', methods=['OPTIONS'])
def api_preflight(_sub):
    return ('', 204)

def db():
    conn = sqlite3.connect(DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS users(
        name TEXT PRIMARY KEY,
        state TEXT NOT NULL DEFAULT '{}',
        updated REAL NOT NULL DEFAULT 0
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS banned(
        name TEXT PRIMARY KEY,
        banned_at REAL NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS banned_dev(
        device TEXT PRIMARY KEY,
        banned_at REAL NOT NULL
    )''')
    for col, ddl in [('device', 'TEXT NOT NULL DEFAULT ""'),
                     ('ua', 'TEXT NOT NULL DEFAULT ""'),
                     ('seen', 'REAL NOT NULL DEFAULT 0'),
                     ('last_ip', 'TEXT NOT NULL DEFAULT ""')]:
        try:
            conn.execute('ALTER TABLE users ADD COLUMN %s %s' % (col, ddl))
        except Exception:
            pass
    conn.execute('''CREATE TABLE IF NOT EXISTS allowed(
        name TEXT PRIMARY KEY,
        added_at REAL NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS banned_model(
        model TEXT PRIMARY KEY,
        banned_at REAL NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS blocked_tries(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        model TEXT NOT NULL,
        ua TEXT NOT NULL,
        ts REAL NOT NULL
    )''')
    return conn

# ---------- 机型识别：把 UA 转成人能读的「机型 · 浏览器」 ----------
import re
# 常见机型代号 → 市场名称（可按需补充）
MODEL_NAMES = {
    '2304FPN6DC': '小米 13 Ultra', '2304FPN6BC': '小米 13 Ultra',
    '2210132C': '小米 13 Pro', '2211133C': '小米 13', '22127RK46C': '小米 13',
    '23127PN0CC': '小米 14', '23116PN5BC': '小米 14 Pro', '2311DRK48C': '小米 14',
    '23013RK75C': '红米 K60', '23078RKD5C': '红米 K60 至尊版', '2312DRA50C': '红米 K70',
    'ALN-AL00': '华为 Mate 60 Pro', 'ALN-AL80': '华为 Mate 60 Pro',
    'MNA-AL00': '华为 P60', 'BRA-AL00': '华为 Mate 60',
    'SM-S9180': '三星 S23 Ultra', 'SM-S9280': '三星 S24 Ultra', 'SM-G9910': '三星 S21',
    'V2241A': 'vivo X90', 'V2309A': 'vivo X100', 'PGZ110': 'OPPO Reno8',
    'PKC110': 'OPPO Find X6', 'PHK110': '一加 11', 'PJD110': '一加 12',
}

def model_name(code):
    if not code:
        return ''
    c = code.strip()
    if c in MODEL_NAMES:
        return MODEL_NAMES[c]
    up = c.upper()
    if re.match(r'^2\d{3}[A-Z0-9]{3,}$', up):
        return '小米/红米 ' + c
    if up.startswith('SM-'):
        return '三星 ' + c
    if re.match(r'^V\d{4}[A-Z]?$', up):
        return 'vivo ' + c
    if re.match(r'^P[A-Z]{2}\d{3}$', up):
        return 'OPPO/一加 ' + c
    if re.match(r'^[A-Z]{3}-[A-Z0-9]{2,}$', up):
        return '华为/荣耀 ' + c
    return c

def ua_parts(ua):
    """返回 (机型, 浏览器)"""
    ua = ua or ''
    if not ua:
        return ('', '')
    model = ''
    if 'iPhone' in ua:
        model = 'iPhone'
    elif 'iPad' in ua:
        model = 'iPad'
    elif 'Android' in ua:
        m = re.search(r'Android[\s\d.]+;\s*([^;)]+?)(?:\s+Build|\)|;)', ua)
        if m:
            model = m.group(1).strip()
            # 去掉语言/地区后缀，如 "zh-cn"
            model = re.sub(r'\s*(zh|en|ja|ko)-[a-z]{2}$', '', model, flags=re.I)
            model = model.replace('_', ' ')
            model = model_name(model) or model
            # 部分机型带 "M2102K1AC" 这类代号，保留
        else:
            model = 'Android'
    elif 'Windows' in ua:
        model = 'Windows 电脑'
    elif 'Macintosh' in ua:
        model = 'Mac'
    elif 'Linux' in ua:
        model = 'Linux'
    else:
        model = '未知设备'
    if 'MicroMessenger' in ua:
        br = '微信'
    elif 'QQ/' in ua or ' QQ' in ua:
        br = 'QQ'
    elif 'Edg/' in ua:
        br = 'Edge'
    elif 'CriOS' in ua or 'Chrome/' in ua:
        br = 'Chrome'
    elif 'FxiOS' in ua or 'Firefox' in ua:
        br = 'Firefox'
    elif 'Safari' in ua:
        br = 'Safari'
    else:
        br = '未知浏览器'
    return (model, br)

def ua_label(ua):
    m, b = ua_parts(ua)
    if not m and not b:
        return ''
    return (m + ' · ' + b).strip(' ·')

def ua_model(ua):
    return ua_parts(ua)[0]

def whitelist_on(conn):
    return conn.execute('SELECT COUNT(*) FROM allowed').fetchone()[0] > 0

# ---------- 管理员密钥（自动生成，见同目录 admin_key.txt） ----------
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin_key.txt')
def admin_key():
    try:
        with open(KEY_FILE) as f:
            k = f.read().strip()
        if k:
            return k
    except Exception:
        pass
    import secrets
    k = secrets.token_hex(4).upper()
    with open(KEY_FILE, 'w') as f:
        f.write(k)
    return k

def is_banned(conn, name):
    if conn.execute('SELECT 1 FROM banned WHERE name=?', (name,)).fetchone():
        return True
    return False

def dev_banned(conn, dev):
    if dev and conn.execute('SELECT 1 FROM banned_dev WHERE device=?', (dev,)).fetchone():
        return True
    return False

@app.route('/api/admin/users')
def admin_users():
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    conn = db()
    rows = conn.execute('''SELECT u.name, u.updated, u.device, u.ua, u.seen, (b.name IS NOT NULL), (bd.device IS NOT NULL), (a.name IS NOT NULL), u.state
                           FROM users u
                           LEFT JOIN banned b ON u.name=b.name
                           LEFT JOIN banned_dev bd ON u.device=bd.device
                           LEFT JOIN allowed a ON u.name=a.name
                           ORDER BY u.updated DESC''').fetchall()
    wl = conn.execute('SELECT COUNT(*) FROM allowed').fetchone()[0]
    out = []
    for r in rows:
        try:
            st = json.loads(r[8] or '{}')
            words = sum(len(v) for v in st.values() if isinstance(v, dict))
        except Exception:
            words = 0
        out.append({'name': r[0], 'updated': int(r[1] or 0), 'device': r[2] or '',
                    'ua': ua_label(r[3]), 'seen': int(r[4] or 0), 'banned': bool(r[5]),
                    'dev_banned': bool(r[6]), 'allowed': bool(r[7]), 'words': words})
    models = [{'model': r[0], 'at': int(r[1])} for r in conn.execute('SELECT model, banned_at FROM banned_model ORDER BY banned_at DESC')]
    tries = [{'name': r[0], 'model': r[1], 'ts': int(r[2])} for r in conn.execute('SELECT name, model, ts FROM blocked_tries ORDER BY ts DESC LIMIT 30')]
    return jsonify({'ok': True, 'whitelist_on': wl > 0, 'users': out, 'models': models, 'tries': tries})

@app.route('/api/admin/ban')
def admin_ban():
    name = request.args.get('name', '').strip()
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    if not name:
        return jsonify({'ok': False, 'error': '缺少 name'}), 400
    conn = db()
    conn.execute('INSERT OR REPLACE INTO banned(name, banned_at) VALUES(?,?)', (name, time.time()))
    # 连带封禁该用户当前使用的设备（nodev=1 时只封昵称）
    dev = ''
    if request.args.get('nodev', '') != '1':
        row = conn.execute('SELECT device FROM users WHERE name=?', (name,)).fetchone()
        dev = (row[0] if row and row[0] else '') or request.args.get('device', '').strip()
    if dev:
        conn.execute('INSERT OR REPLACE INTO banned_dev(device, banned_at) VALUES(?,?)', (dev, time.time()))
    conn.commit()
    return jsonify({'ok': True, 'banned': name, 'device_banned': bool(dev)})

@app.route('/api/admin/unban')
def admin_unban():
    name = request.args.get('name', '').strip()
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    conn = db()
    # 同时解封该用户名下设备
    row = conn.execute('SELECT device FROM users WHERE name=?', (name,)).fetchone()
    conn.execute('DELETE FROM banned WHERE name=?', (name,))
    if row and row[0]:
        conn.execute('DELETE FROM banned_dev WHERE device=?', (row[0],))
    conn.commit()
    return jsonify({'ok': True, 'unbanned': name})

# ---------- 白名单模式：加入任何人后，仅白名单内用户可登录 ----------
@app.route('/api/admin/allow')
def admin_allow():
    name = request.args.get('name', '').strip()
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    if not name:
        return jsonify({'ok': False, 'error': '缺少 name'}), 400
    conn = db()
    conn.execute('INSERT OR REPLACE INTO allowed(name, added_at) VALUES(?,?)', (name, time.time()))
    conn.commit()
    return jsonify({'ok': True, 'allowed': name, 'whitelist_on': True})

@app.route('/api/admin/disallow')
def admin_disallow():
    name = request.args.get('name', '').strip()
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    conn = db()
    conn.execute('DELETE FROM allowed WHERE name=?', (name,))
    n = conn.execute('SELECT COUNT(*) FROM allowed').fetchone()[0]
    conn.commit()
    return jsonify({'ok': True, 'removed': name, 'whitelist_on': n > 0})

@app.route('/api/admin/allowall')
def admin_allowall():
    """把现有全部用户加入白名单（开启白名单前用）"""
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    conn = db()
    conn.execute('INSERT OR REPLACE INTO allowed(name, added_at) SELECT name, ? FROM users', (time.time(),))
    conn.commit()
    n = conn.execute('SELECT COUNT(*) FROM allowed').fetchone()[0]
    return jsonify({'ok': True, 'allowed_count': n})

@app.route('/api/admin/modelban')
def admin_modelban():
    model = request.args.get('model', '').strip()
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    if not model:
        return jsonify({'ok': False, 'error': '缺少 model'}), 400
    conn = db()
    conn.execute('INSERT OR REPLACE INTO banned_model(model, banned_at) VALUES(?,?)', (model, time.time()))
    conn.commit()
    return jsonify({'ok': True, 'model': model})


@app.route('/api/admin/modelunban')
def admin_modelunban():
    model = request.args.get('model', '').strip()
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    conn = db()
    conn.execute('DELETE FROM banned_model WHERE model=?', (model,))
    conn.commit()
    return jsonify({'ok': True, 'removed': model})


@app.route('/api/admin/allowoff')
def admin_allowoff():
    """关闭白名单模式：清空白名单，所有人可登录"""
    if request.args.get('key', '') != admin_key():
        return jsonify({'ok': False, 'error': '密钥错误'}), 403
    conn = db()
    conn.execute('DELETE FROM allowed')
    conn.commit()
    return jsonify({'ok': True, 'whitelist_on': False})


@app.route('/admin')
def admin_page():
    """管理后台页面（需带 key 参数）"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin.html')
    resp = send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'admin.html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route('/')
def index():
    resp = send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'index.html')
    # 页面始终取最新版本，避免用户看到旧缓存
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json or {}
    name = d.get('name', '').strip()
    dev = (d.get('device') or '').strip()[:64]
    ua = (d.get('ua') or request.headers.get('User-Agent') or '')[:400]
    ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()[:60]
    if not name or len(name) > 20:
        return jsonify({'ok': False, 'error': '昵称需为1-20个字符'}), 400
    conn = db()
    if is_banned(conn, name):
        return jsonify({'ok': False, 'error': '该昵称已被停用，请联系管理员'}), 403
    if dev_banned(conn, dev):
        return jsonify({'ok': False, 'error': '此设备已被停用，请联系管理员'}), 403
    mdl = ua_model(ua)
    if mdl and conn.execute('SELECT 1 FROM banned_model WHERE model=?', (mdl,)).fetchone():
        conn.execute('INSERT INTO blocked_tries(name, model, ua, ts) VALUES(?,?,?,?)', (name, mdl, ua, time.time()))
        conn.commit()
        return jsonify({'ok': False, 'error': '此设备已被停用，请联系管理员'}), 403
    if whitelist_on(conn) and not conn.execute('SELECT 1 FROM allowed WHERE name=?', (name,)).fetchone():
        return jsonify({'ok': False, 'error': '该应用仅限受邀用户使用，请联系管理员'}), 403
    row = conn.execute('SELECT state FROM users WHERE name=?', (name,)).fetchone()
    if row is None:
        conn.execute('INSERT INTO users(name, state, updated, device, ua, seen, last_ip) VALUES(?,?,?,?,?,?,?)',
                     (name, '{}', time.time(), dev, ua, time.time(), ip))
        conn.commit()
        return jsonify({'ok': True, 'new': True, 'state': {}})
    else:
        # 记录/更新该用户的设备、机型、最近登录时间
        conn.execute('UPDATE users SET device=?, ua=?, seen=?, last_ip=? WHERE name=?',
                     (dev, ua, time.time(), ip, name))
        conn.commit()
    return jsonify({'ok': True, 'new': False, 'state': json.loads(row[0])})

@app.route('/api/progress', methods=['GET'])
def get_progress():
    name = request.args.get('name', '').strip()
    conn = db()
    row = conn.execute('SELECT state FROM users WHERE name=?', (name,)).fetchone()
    return jsonify({'ok': True, 'state': json.loads(row[0]) if row else {}})

@app.route('/api/progress', methods=['POST'])
def save_progress():
    d = request.json or {}
    name = d.get('name', '').strip()
    state = d.get('state')
    if not name or state is None:
        return jsonify({'ok': False}), 400
    conn = db()
    if is_banned(conn, name):
        return jsonify({'ok': False, 'error': '该昵称已被停用'}), 403
    dev = (d.get('device') or '').strip()[:64]
    if dev_banned(conn, dev):
        return jsonify({'ok': False, 'error': '此设备已被停用'}), 403
    if whitelist_on(conn) and not conn.execute('SELECT 1 FROM allowed WHERE name=?', (name,)).fetchone():
        return jsonify({'ok': False, 'error': '该应用仅限受邀用户使用'}), 403
    conn.execute('''INSERT INTO users(name, state, updated, device) VALUES(?,?,?,?)
                     ON CONFLICT(name) DO UPDATE SET state=excluded.state, updated=excluded.updated''',
                 (name, json.dumps(state, ensure_ascii=False), time.time(), dev))
    conn.commit()
    return jsonify({'ok': True})


TR_CACHE = {}
TR_TABLE = "CREATE TABLE IF NOT EXISTS trans(word TEXT PRIMARY KEY, zh TEXT NOT NULL)"

def _translate(word):
    """多源尝试翻译单词，返回中文或 None"""
    import urllib.request, urllib.parse
    try:
        url = 'https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=zh-CN&dt=t&q=' + urllib.parse.quote(word)
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode('utf-8'))
        txt = ''.join(seg[0] for seg in (data[0] or []) if seg and seg[0])
        if txt and txt.strip().lower() != word.strip().lower():
            return txt.strip()
    except Exception:
        pass
    try:
        url = 'https://api.mymemory.translated.net/get?q=' + urllib.parse.quote(word) + '&langpair=en|zh-CN'
        with urllib.request.urlopen(url, timeout=6) as r:
            d = json.loads(r.read().decode('utf-8'))
        t = (d.get('responseData') or {}).get('translatedText') or ''
        if t and 'MYMEMORY WARNING' not in t.upper() and not all(ord(c) < 128 for c in t):
            return t.strip()
    except Exception:
        pass
    return None

@app.route('/api/trans')
def trans():
    word = (request.args.get('w') or '').strip().lower()[:40]
    if not word or not word.replace('-', '').replace("'", '').isalpha():
        return jsonify({'ok': False, 'zh': ''})
    if word in TR_CACHE:
        return jsonify({'ok': True, 'zh': TR_CACHE[word]})
    conn = db()
    conn.execute(TR_TABLE)
    row = conn.execute('SELECT zh FROM trans WHERE word=?', (word,)).fetchone()
    if row:
        TR_CACHE[word] = row[0]
        return jsonify({'ok': True, 'zh': row[0]})
    zh = _translate(word)
    if zh:
        conn.execute('INSERT OR REPLACE INTO trans(word, zh) VALUES(?,?)', (word, zh))
        conn.commit()
        TR_CACHE[word] = zh
        return jsonify({'ok': True, 'zh': zh})
    return jsonify({'ok': False, 'zh': ''})

@app.route('/api/health')
def health():
    return jsonify({'ok': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port, threaded=True)
