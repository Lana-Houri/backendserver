from flask import Flask, request, jsonify, abort
from db_config import DB_CONFIG
from models import db, CellData
from sqlalchemy import func, select
from datetime import datetime
from flask_cors import CORS
from dotenv import load_dotenv
import os
import jwt

app = Flask(__name__)

load_dotenv()
DB_USER = os.getenv("DB_USER")
DB_PASSWORD= os.getenv("DB_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY")

app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG
app.config["SECRET_KEY"]= SECRET_KEY

from .extension import db, ma, bcrypt
db.init_app(app)
ma.init_app(app)
bcrypt.init_app(app)

CORS(app)

from .model.user import User, user_schema
def create_token(user_id):
    payload = {
    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=4),
    'iat': datetime.datetime.utcnow(),
    'sub': str(user_id)
    }
    return jwt.encode(
    payload,
    SECRET_KEY,
    algorithm='HS256'
)

def extract_auth_token(authenticated_request):
    auth_header = authenticated_request.headers.get('Authorization')
    if auth_header:
        return auth_header.split(" ")[1]
    else:
        return None
    
def decode_token(token):
    payload = jwt.decode(token, SECRET_KEY, 'HS256')
    return payload['sub']

@app.route('/user', methods=['POST'])
def new_user():

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415
    
    user_name= request.json.get("user_name")
    password= request.json.get("password")

    if not user_name or not password:
        return jsonify({"error": "No username or no password"}),400
    
    old_user= User.query.filter_by(user_name=user_name).first()
    if old_user:
        return jsonify({"error": "this user already exist"}), 409

    NEW_USER = User(user_name = user_name, password = password)

    db.session.add(NEW_USER)
    db.session.commit()

    return jsonify(user_schema.dump(NEW_USER)),201

@app.route('/authentication', methods=['POST'])
def authentication():

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415
    
    user_name= request.json.get("user_name")
    password= request.json.get("password")

    if not user_name or not password:
        abort(400)

    user = db.session.execute(select(User).filter(User.user_name==user_name)).scalar_one_or_none()

    if not user:
        abort(403)
    
    if not bcrypt.check_password_hash(user.hashed_password, password):
        abort(403)
    
    token= create_token(user.id)

    return jsonify({"token": token})

# ------------------- Submit Endpoint -------------------
@app.route('/submit', methods=['POST'])
def submit_data():
    data = request.json
    cell_entry = CellData(
        timestamp=data.get('timestamp'),
        operator=data.get('operator'),
        signal_power=data.get('signal_power'),
        snr=data.get('snr'),
        network_type=data.get('network_type'),
        band=data.get('band'),
        cell_id=data.get('cell_id'),
        device_ip=data.get('device_ip'),
        device_mac=data.get('device_mac')
    )
    db.session.add(cell_entry)
    db.session.commit()
    return jsonify({"status": "success"}), 200

# ------------------- Operator Stats Endpoint -------------------
@app.route('/stats/operator', methods=['GET'])
def operator_stats():
    start_time = request.args.get('from')
    end_time = request.args.get('to')

    if not start_time or not end_time:
        return jsonify({"error": "Please provide 'from' and 'to' query parameters."}), 400

    try:
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({"error": "Invalid datetime format. Use YYYY-MM-DD HH:MM:SS"}), 400

    results = db.session.query(
        CellData.operator, func.count(CellData.id)
    ).filter(
        CellData.timestamp >= start_time,
        CellData.timestamp <= end_time
    ).group_by(CellData.operator).all()

    total = sum([count for _, count in results])
    if total == 0:
        return jsonify({"message": "No data found for the specified time range."})

    percentages = {
        operator: f"{round((count / total) * 100, 2)}%"
        for operator, count in results
    }

    return jsonify(percentages), 200



@app.route('/stats/network-type', methods=['GET'])
def network_type_stats():
    start_time = request.args.get('from')
    end_time = request.args.get('to')

    if not start_time or not end_time:
        return jsonify({"error": "Please provide 'from' and 'to' query parameters."}), 400

    try:
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({"error": "Invalid datetime format. Use YYYY-MM-DD HH:MM:SS"}), 400

    # Count entries per network type
    results = db.session.query(
        CellData.network_type, func.count(CellData.id)
    ).filter(
        CellData.timestamp >= start_time,
        CellData.timestamp <= end_time
    ).group_by(CellData.network_type).all()

    total = sum([count for _, count in results])
    if total == 0:
        return jsonify({"message": "No data found for the specified time range."})

    percentages = {
        network_type: f"{round((count / total) * 100, 2)}%"
        for network_type, count in results
    }

    return jsonify(percentages), 200



@app.route('/stats/signal-power', methods=['GET'])
def signal_power_stats():
    start_time = request.args.get('from')
    end_time = request.args.get('to')

    if not start_time or not end_time:
        return jsonify({"error": "Please provide 'from' and 'to' query parameters."}), 400

    try:
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({"error": "Invalid datetime format. Use YYYY-MM-DD HH:MM:SS"}), 400

    results = db.session.query(
        CellData.network_type,
        func.avg(CellData.signal_power)
    ).filter(
        CellData.timestamp >= start_time,
        CellData.timestamp <= end_time
    ).group_by(CellData.network_type).all()

    if not results:
        return jsonify({"message": "No data found for the specified time range."})

    averages = {
        network_type: f"{round(avg_power, 2)} dBm"
        for network_type, avg_power in results
    }

    return jsonify(averages), 200



@app.route('/devices/active', methods=['GET'])
def active_devices():
    # Subquery: for each MAC, get the max timestamp
    subquery = db.session.query(
        CellData.device_mac,
        func.max(CellData.timestamp).label('last_seen')
    ).group_by(CellData.device_mac).subquery()

    # Join to get the IP and full info
    results = db.session.query(
        CellData.device_mac,
        CellData.device_ip,
        subquery.c.last_seen
    ).join(
        subquery,
        (CellData.device_mac == subquery.c.device_mac) &
        (CellData.timestamp == subquery.c.last_seen)
    ).all()

    devices = []
    for mac, ip, last_seen in results:
        devices.append({
            "device_mac": mac,
            "device_ip": ip,
            "last_seen": last_seen
        })

    return jsonify({
        "active_device_count": len(devices),
        "devices": devices
    }), 200


@app.route('/stats/device', methods=['GET'])
def device_stats():
    device_mac = request.args.get('mac')
    start_time = request.args.get('from')
    end_time = request.args.get('to')

    if not device_mac or not start_time or not end_time:
        return jsonify({"error": "Please provide 'mac', 'from', and 'to' parameters."}), 400

    try:
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({"error": "Invalid datetime format. Use YYYY-MM-DD HH:MM:SS"}), 400

    query = db.session.query(
        func.avg(CellData.signal_power).label('avg_signal'),
        func.avg(CellData.snr).label('avg_snr'),
        func.count(CellData.id).label('count')
    ).filter(
        CellData.device_mac == device_mac,
        CellData.timestamp >= start_time,
        CellData.timestamp <= end_time
    ).first()

    if query.count == 0:
        return jsonify({"message": "No data found for that device in the specified time range."}), 404

    return jsonify({
        "device_mac": device_mac,
        "average_signal_power": f"{round(query.avg_signal, 2)} dBm" if query.avg_signal is not None else "N/A",
        "average_snr": f"{round(query.avg_snr, 2)} dB" if query.avg_snr is not None else "N/A",
        "record_count": query.count
    }), 200



# ------------------- Root Endpoint -------------------
@app.route('/')
def home():
    return "Network Analyzer Server is running."

# ------------------- Run Server -------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    
    

