from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import json
import csv
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
captured_packets = []
is_capturing = False
packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0}

def get_protocol_name(proto_num):
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto_num, f"Unknown({proto_num})")

def extract_packet_info(packet):
    """Extract relevant info from packet"""
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = get_protocol_name(ip_layer.proto)
        
        src_port = dst_port = None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        return {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'size': len(packet)
        }
    return None

def packet_callback(packet):
    """Called for each captured packet"""
    global is_capturing
    if not is_capturing:
        return
    
    packet_info = extract_packet_info(packet)
    if packet_info:
        captured_packets.append(packet_info)
        
        proto = packet_info['protocol']
        if proto in packet_stats:
            packet_stats[proto] += 1
        
        socketio.emit('new_packet', packet_info)
        
        if len(captured_packets) > 500:
            captured_packets.pop(0)

def start_sniffer():
    """Start packet capture in background thread"""
    global is_capturing
    is_capturing = True
    sniff(prn=packet_callback, store=False, count=0)

# ========== API ROUTES ==========

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/start', methods=['POST'])
def start_capture():
    global is_capturing
    if not is_capturing:
        thread = threading.Thread(target=start_sniffer)
        thread.daemon = True
        thread.start()
        return jsonify({'status': 'started', 'message': 'Packet capture started'})
    return jsonify({'status': 'already_running', 'message': 'Capture already running'})

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({'status': 'stopped', 'message': 'Packet capture stopped'})

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'total_packets': len(captured_packets),
        'protocol_stats': packet_stats,
        'recent_packets': captured_packets[-20:]
    })

@app.route('/api/clear', methods=['POST'])
def clear_packets():
    global captured_packets, packet_stats
    captured_packets = []
    packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
    return jsonify({'status': 'cleared', 'message': 'All packets cleared'})

# ========== EXPORT ROUTES (USING GET FOR DOWNLOAD) ==========

@app.route('/api/export/json', methods=['GET'])
def api_export_json():
    if not captured_packets:
        return jsonify({'error': 'No packets to export'}), 400
    
    json_data = json.dumps(captured_packets, indent=2)
    return send_file(
        io.BytesIO(json_data.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'packets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    )

@app.route('/api/export/csv', methods=['GET'])
def api_export_csv():
    if not captured_packets:
        return jsonify({'error': 'No packets to export'}), 400
    
    output = io.StringIO()
    fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'size']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for packet in captured_packets:
        row = {k: packet.get(k, '') for k in fieldnames}
        writer.writerow(row)
    
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'packets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/api/export/txt', methods=['GET'])
def api_export_txt():
    if not captured_packets:
        return jsonify({'error': 'No packets to export'}), 400
    
    output = io.StringIO()
    
    output.write("=" * 80 + "\n")
    output.write("PACKET CAPTURE EXPORT\n")
    output.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    output.write(f"Total Packets: {len(captured_packets)}\n")
    output.write(f"TCP: {packet_stats['TCP']} | UDP: {packet_stats['UDP']} | ICMP: {packet_stats['ICMP']}\n")
    output.write("=" * 80 + "\n\n")
    
    for i, p in enumerate(captured_packets, 1):
        output.write(f"Packet #{i}\n")
        output.write(f"  Timestamp: {p['timestamp']}\n")
        output.write(f"  Source: {p['src_ip']}:{p.get('src_port', 'N/A')}\n")
        output.write(f"  Destination: {p['dst_ip']}:{p.get('dst_port', 'N/A')}\n")
        output.write(f"  Protocol: {p['protocol']}\n")
        output.write(f"  Size: {p['size']} bytes\n")
        output.write("-" * 40 + "\n")
    
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'packets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    )

# ========== WEBSOCKET EVENTS ==========

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'data': 'Connected to packet sniffer'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# ========== MAIN ==========

if __name__ == '__main__':
    print("=" * 60)
    print("🌐 Network Packet Sniffer Web Dashboard")
    print("=" * 60)
    print("🌐 Starting server at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop")
    print("=" * 60)
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
