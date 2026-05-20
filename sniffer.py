from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import json

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

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print('Client connected')
    emit('connected', {'data': 'Connected to packet sniffer'})

if __name__ == '__main__':
    print("=" * 60)
    print("🌐 Network Packet Sniffer Web Dashboard")
    print("=" * 60)
    print("Starting server at: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)