from flask import Flask, request, jsonify
from config import SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS
from models import db, CellData
from sqlalchemy import func
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS

db.init_app(app)

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
    
    

