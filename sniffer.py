from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import json
import csv
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
captured_packets = []
is_capturing = False
packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0}

# Create exports folder if it doesn't exist
EXPORT_FOLDER = 'exports'
if not os.path.exists(EXPORT_FOLDER):
    os.makedirs(EXPORT_FOLDER)

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
        
        # Update statistics
        proto = packet_info['protocol']
        if proto in packet_stats:
            packet_stats[proto] += 1
        
        # Send to connected clients via WebSocket
        socketio.emit('new_packet', packet_info)
        
        # Keep only last 500 packets in memory
        if len(captured_packets) > 500:
            captured_packets.pop(0)

def start_sniffer():
    """Start packet capture in background thread"""
    global is_capturing
    is_capturing = True
    sniff(prn=packet_callback, store=False, count=0)

# ========== EXPORT FUNCTIONS ==========

def export_to_json():
    """Export captured packets to JSON file"""
    if not captured_packets:
        return None
    
    filename = f"{EXPORT_FOLDER}/packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(captured_packets, f, indent=2)
    return filename

def export_to_csv():
    """Export captured packets to CSV file"""
    if not captured_packets:
        return None
    
    filename = f"{EXPORT_FOLDER}/packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, 'w', newline='') as f:
        # Get all field names from first packet
        fieldnames = captured_packets[0].keys()
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(captured_packets)
    return filename

def export_to_txt():
    """Export captured packets to readable TXT file"""
    if not captured_packets:
        return None
    
    filename = f"{EXPORT_FOLDER}/packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("PACKET CAPTURE EXPORT\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Packets: {len(captured_packets)}\n")
        f.write("=" * 80 + "\n\n")
        
        for i, p in enumerate(captured_packets, 1):
            f.write(f"Packet #{i}\n")
            f.write(f"  Timestamp: {p['timestamp']}\n")
            f.write(f"  Source: {p['src_ip']}:{p.get('src_port', 'N/A')}\n")
            f.write(f"  Destination: {p['dst_ip']}:{p.get('dst_port', 'N/A')}\n")
            f.write(f"  Protocol: {p['protocol']}\n")
            f.write(f"  Size: {p['size']} bytes\n")
            f.write("-" * 40 + "\n")
    
    return filename

# ========== API ROUTES ==========

@app.route('/')
def index():
    """Serve the dashboard"""
    return render_template('dashboard.html')

@app.route('/api/start', methods=['POST'])
def start_capture():
    """API endpoint to start capturing"""
    global is_capturing
    if not is_capturing:
        thread = threading.Thread(target=start_sniffer)
        thread.daemon = True
        thread.start()
        return jsonify({'status': 'started', 'message': 'Packet capture started'})
    return jsonify({'status': 'already_running', 'message': 'Capture already running'})

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """API endpoint to stop capturing"""
    global is_capturing
    is_capturing = False
    return jsonify({'status': 'stopped', 'message': 'Packet capture stopped'})

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify({
        'total_packets': len(captured_packets),
        'protocol_stats': packet_stats,
        'recent_packets': captured_packets[-20:]  # Last 20 packets
    })

@app.route('/api/clear', methods=['POST'])
def clear_packets():
    """Clear all captured packets"""
    global captured_packets, packet_stats
    captured_packets = []
    packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
    return jsonify({'status': 'cleared', 'message': 'All packets cleared'})

# ========== EXPORT API ROUTES ==========

@app.route('/api/export/json', methods=['POST'])
def api_export_json():
    """Export packets to JSON"""
    filename = export_to_json()
    if filename:
        return jsonify({'status': 'success', 'file': filename, 'count': len(captured_packets)})
    return jsonify({'status': 'error', 'message': 'No packets to export'})

@app.route('/api/export/csv', methods=['POST'])
def api_export_csv():
    """Export packets to CSV"""
    filename = export_to_csv()
    if filename:
        return jsonify({'status': 'success', 'file': filename, 'count': len(captured_packets)})
    return jsonify({'status': 'error', 'message': 'No packets to export'})

@app.route('/api/export/txt', methods=['POST'])
def api_export_txt():
    """Export packets to TXT"""
    filename = export_to_txt()
    if filename:
        return jsonify({'status': 'success', 'file': filename, 'count': len(captured_packets)})
    return jsonify({'status': 'error', 'message': 'No packets to export'})

@app.route('/api/exports/list', methods=['GET'])
def list_exports():
    """List all exported files"""
    files = []
    if os.path.exists(EXPORT_FOLDER):
        for f in os.listdir(EXPORT_FOLDER):
            filepath = os.path.join(EXPORT_FOLDER, f)
            if os.path.isfile(filepath):
                files.append({
                    'name': f,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
                })
    return jsonify(files)

@app.route('/api/exports/download/<filename>', methods=['GET'])
def download_export(filename):
    """Download an exported file"""
    filepath = os.path.join(EXPORT_FOLDER, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

# ========== WEBSOCKET EVENTS ==========

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print('Client connected')
    emit('connected', {'data': 'Connected to packet sniffer'})

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('Client disconnected')

# ========== MAIN ==========

if __name__ == '__main__':
    print("=" * 60)
    print("🌐 Network Packet Sniffer Web Dashboard")
    print("=" * 60)
    print(f"📁 Exports will be saved to: {os.path.abspath(EXPORT_FOLDER)}")
    print("🌐 Starting server at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop")
    print("=" * 60)
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
