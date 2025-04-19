from flask import Flask, request, jsonify, abort
from .db_config import DB_CONFIG
from .model.user import User
from .models import CellData 
from sqlalchemy import func, select
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from dotenv import load_dotenv
import os
import jwt
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
ma = Marshmallow()
bcrypt = Bcrypt()

app = Flask(__name__)

load_dotenv()
DB_USER = os.getenv("DB_USER")
DB_PASSWORD= os.getenv("DB_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY")

app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG
app.config["SECRET_KEY"]= SECRET_KEY

# from .extension import db, ma, bcrypt
db.init_app(app)
ma.init_app(app)
bcrypt.init_app(app)

CORS(app)

from .model.user import User, user_schema
def create_token(user_id):
    payload = {
    'exp': datetime.now(timezone.utc) + datetime.timedelta(days=4),
    'iat': datetime.now(timezone.utc),
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

# registration of new users
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

# logging in 
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
    
    # Convert timestamp string to datetime object if it's provided as string
    timestamp = data.get('timestamp')
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return jsonify({"error": "Invalid timestamp format. Use YYYY-MM-DD HH:MM:SS"}), 400
    else:
        timestamp = datetime.now()  # Use current time if not provided
        
    cell_entry = CellData(
        timestamp=timestamp,
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

def parse_time_range(request):
    """
    Parse and validate time range from request parameters
    
    Returns:
        tuple: (start_datetime, end_datetime, error_response)
        If validation fails, first two elements will be None and error_response will contain the error
    """
    start_time = request.args.get('from')
    end_time = request.args.get('to')

    # Check if both parameters are provided
    if not start_time or not end_time:
        return None, None, (jsonify({
            "error": "Please provide both 'from' and 'to' query parameters."
        }), 400)

    try:
        # Parse datetime strings
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
        
        # Check if end time is before start time
        if end_dt < start_dt:
            return None, None, (jsonify({
                "error": "Invalid time range: 'to' date must be after 'from' date."
            }), 400)
        
        # Check if time range is too large (optional, adjust as needed)
        max_days = 90  # Maximum 90 days range
        if (end_dt - start_dt).days > max_days:
            return None, None, (jsonify({
                "error": f"Time range too large. Maximum allowed range is {max_days} days."
            }), 400)
        
        # Check if dates are in the future (optional)
        now = datetime.now()
        if end_dt > now:
            return None, None, (jsonify({
                "warning": "End date is in the future. Using current time instead.",
                "original_end": end_time,
                "adjusted_end": now.strftime('%Y-%m-%d %H:%M:%S')
            }), 200)
            # Note: This returns a warning but doesn't fail the request
            # You could also choose to adjust end_dt = now and continue
        
        return start_dt, end_dt, None
        
    except ValueError:
        return None, None, (jsonify({
            "error": "Invalid datetime format. Use YYYY-MM-DD HH:MM:SS"
        }), 400)

# Calculates the percentage of connection time per mobile operator (e.g., Touch, Alfa) between two user-specified timestamps (from and to).
@app.route('/stats/operator', methods=['GET'])
# Calculates the percentage of connection time per mobile operator (e.g., Touch, Alfa) between two user-specified timestamps (from and to).
@app.route('/stats/operator', methods=['GET'])
def operator_stats():
    start_dt, end_dt, error = parse_time_range(request)
    if error:
        # If it's a warning with status code 200, adjust the end_dt to now
        if error[1] == 200 and "warning" in error[0].json:
            end_dt = datetime.now()
        else:
            return error
    
    # Get total records in the time range
    results = db.session.query(
        CellData.operator, func.count(CellData.id)
    ).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).group_by(CellData.operator).all()

    total = sum([count for _, count in results])
    if total == 0:
        return jsonify({"message": "No data found for the specified time range."}), 404

    percentages = {
        operator: f"{round((count / total) * 100, 2)}%"
        for operator, count in results
    }

    return jsonify({
        "time_range": {
            "from": start_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "to": end_dt.strftime('%Y-%m-%d %H:%M:%S')
        },
        "operator_stats": percentages
    }), 200


# Calculates how much time was spent on each network type (e.g., 4G, 3G, 2G) as a percentage between the given timestamps.
@app.route('/stats/network-type', methods=['GET'])
def network_type_stats():
    start_dt, end_dt, error = parse_time_range(request)
    if error:
        # If it's a warning with status code 200, adjust the end_dt to now
        if error[1] == 200 and "warning" in error[0].json:
            end_dt = datetime.now()
        else:
            return error
    
    # Count entries per network type
    results = db.session.query(
        CellData.network_type, func.count(CellData.id)
    ).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).group_by(CellData.network_type).all()

    total = sum([count for _, count in results])
    if total == 0:
        return jsonify({"message": "No data found for the specified time range."}), 404

    percentages = {
        network_type: f"{round((count / total) * 100, 2)}%"
        for network_type, count in results
    }

    return jsonify({
        "time_range": {
            "from": start_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "to": end_dt.strftime('%Y-%m-%d %H:%M:%S')
        },
        "network_type_stats": percentages
    }), 200


# Calculates the average signal power (in dBm) for each network type (2G, 3G, 4G) in a time range.
@app.route('/stats/signal-power', methods=['GET'])
def signal_power_stats():
    start_dt, end_dt, error = parse_time_range(request)
    if error:
        # If it's a warning with status code 200, adjust the end_dt to now
        if error[1] == 200 and "warning" in error[0].json:
            end_dt = datetime.now()
        else:
            return error
    
    results = db.session.query(
        CellData.network_type,
        func.avg(CellData.signal_power).label('avg_power'),
        func.count(CellData.id).label('count')
    ).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).group_by(CellData.network_type).all()

    if not results:
        return jsonify({"message": "No data found for the specified time range."}), 404

    averages = {
        network_type: {
            "average_signal_power": f"{round(avg_power, 2)} dBm" if avg_power is not None else "N/A",
            "record_count": count
        }
        for network_type, avg_power, count in results
    }

    return jsonify({
        "time_range": {
            "from": start_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "to": end_dt.strftime('%Y-%m-%d %H:%M:%S')
        },
        "signal_power_stats": averages
    }), 200
    
    
# Calculates the average SNR (in dB) for each network type (2G, 3G, 4G) in a time range.
@app.route('/stats/snr', methods=['GET'])
def snr_stats():
    start_dt, end_dt, error = parse_time_range(request)
    if error:
        # If it's a warning with status code 200, adjust the end_dt to now
        if error[1] == 200 and "warning" in error[0].json:
            end_dt = datetime.now()
        else:
            return error
    
    results = db.session.query(
        CellData.network_type,
        func.avg(CellData.snr).label('avg_snr'),
        func.count(CellData.id).label('count')
    ).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt,
        CellData.snr.isnot(None)  # Only include records with SNR values
    ).group_by(CellData.network_type).all()
    
    if not results:
        return jsonify({"message": "No SNR data found for the specified time range."}), 404
    
    averages = {
        network_type: {
            "average_snr": f"{round(avg_snr, 2)} dB" if avg_snr is not None else "N/A",
            "record_count": count
        }
        for network_type, avg_snr, count in results
    }
    
    return jsonify({
        "time_range": {
            "from": start_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "to": end_dt.strftime('%Y-%m-%d %H:%M:%S')
        },
        "snr_stats": averages
    }), 200


# Shows statistics for a specific device (avg signal, snr, count)
@app.route('/stats/device', methods=['GET'])
def device_stats():
    device_mac = request.args.get('mac')
    if not device_mac:
        return jsonify({"error": "Please provide 'mac' parameter."}), 400
    
    start_dt, end_dt, error = parse_time_range(request)
    if error:
        # If it's a warning with status code 200, adjust the end_dt to now
        if error[1] == 200 and "warning" in error[0].json:
            end_dt = datetime.now()
        else:
            return error

    query = db.session.query(
        func.avg(CellData.signal_power).label('avg_signal'),
        func.avg(CellData.snr).label('avg_snr'),
        func.count(CellData.id).label('count')
    ).filter(
        CellData.device_mac == device_mac,
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).first()

    if query.count == 0:
        return jsonify({"message": "No data found for that device in the specified time range."}), 404

    # Get network type distribution for this device
    network_types = db.session.query(
        CellData.network_type,
        func.count(CellData.id).label('count')
    ).filter(
        CellData.device_mac == device_mac,
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).group_by(CellData.network_type).all()
    
    network_distribution = {
        network_type: f"{round((count / query.count) * 100, 2)}%"
        for network_type, count in network_types
    }

    return jsonify({
        "time_range": {
            "from": start_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "to": end_dt.strftime('%Y-%m-%d %H:%M:%S')
        },
        "device_mac": device_mac,
        "average_signal_power": f"{round(query.avg_signal, 2)} dBm" if query.avg_signal is not None else "N/A",
        "average_snr": f"{round(query.avg_snr, 2)} dB" if query.avg_snr is not None else "N/A",
        "network_type_distribution": network_distribution,
        "record_count": query.count
    }), 200

# Returns currently active devices (by MAC address and IP), and the last time they connected.
@app.route('/devices/active', methods=['GET'])
def active_devices():
    # Get time threshold (default: devices active in the last 24 hours)
    hours = request.args.get('hours', 24, type=int)
    threshold = datetime.now() - timedelta(hours=hours)
    
    # Subquery: for each MAC, get the max timestamp
    subquery = db.session.query(
        CellData.device_mac,
        func.max(CellData.timestamp).label('last_seen')
    ).filter(
        CellData.timestamp >= threshold
    ).group_by(CellData.device_mac).subquery()
    
    # Join to get the IP and full info
    results = db.session.query(
        CellData.device_mac,
        CellData.device_ip,
        subquery.c.last_seen,
        CellData.operator,
        CellData.network_type
    ).join(
        subquery,
        (CellData.device_mac == subquery.c.device_mac) &
        (CellData.timestamp == subquery.c.last_seen)
    ).all()
    
    devices = []
    for mac, ip, last_seen, operator, network_type in results:
        devices.append({
            "device_mac": mac,
            "device_ip": ip,
            "last_seen": last_seen.strftime('%Y-%m-%d %H:%M:%S') if last_seen else None,
            "current_operator": operator,
            "current_network_type": network_type
        })
    
    return jsonify({
        "active_device_count": len(devices),
        "time_threshold": f"Last {hours} hours",
        "devices": devices
    }), 200

# Provides a summary of all statistics for a dashboard --> for web interface
@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Get time range (default: last 24 hours)
    hours = request.args.get('hours', 24, type=int)
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=hours)
    
    # Get total records
    total_count = db.session.query(func.count(CellData.id)).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).scalar()
    
    # Get operator distribution
    operators = db.session.query(
        CellData.operator,
        func.count(CellData.id).label('count')
    ).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).group_by(CellData.operator).all()
    
    operator_stats = {
        operator: {
            "count": count,
            "percentage": round((count / total_count) * 100, 2) if total_count > 0 else 0
        }
        for operator, count in operators
    }
    
    # Get network type distribution
    network_types = db.session.query(
        CellData.network_type,
        func.count(CellData.id).label('count')
    ).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).group_by(CellData.network_type).all()
    
    network_type_stats = {
        network_type: {
            "count": count,
            "percentage": round((count / total_count) * 100, 2) if total_count > 0 else 0
        }
        for network_type, count in network_types
    }
    
    # Get active devices count
    active_devices_count = db.session.query(
        func.count(func.distinct(CellData.device_mac))
    ).filter(
        CellData.timestamp >= start_dt,
        CellData.timestamp <= end_dt
    ).scalar()
    
    return jsonify({
        "time_range": {
            "from": start_dt.strftime('%Y-%m-%d %H:%M:%S'),
            "to": end_dt.strftime('%Y-%m-%d %H:%M:%S')
        },
        "total_records": total_count,
        "active_devices_count": active_devices_count,
        "operator_stats": operator_stats,
        "network_type_stats": network_type_stats
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
    
    

