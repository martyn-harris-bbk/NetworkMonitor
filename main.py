#!/usr/bin/env python3.6
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading
import scapy.all as scapy
import geoip2.database
import socket

# Initialize the Flask application
app = Flask(__name__)
socketio = SocketIO(app)

# Load GeoLite2 database for IP geolocation
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# Store IP locations and packet counts
ip_locations = {}
packet_counts = {}
total_packets = 0
previous_location = None

# Function to update packet counts
def update_packet_count(start, end):
    global total_packets
    key = f"{start['lat']},{start['lon']}->{end['lat']},{end['lon']}"
    packet_counts[key] = packet_counts.get(key, 0) + 1
    total_packets += 1
    return packet_counts[key]

# Function to resolve domain names
def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# Function to handle packet capture using Scapy
def packet_callback(packet):
    global previous_location
    if packet.haslayer(scapy.IP):
        ip = packet[scapy.IP].src
        try:
            response = geoip_reader.city(ip)
            if response.location.latitude and response.location.longitude:
                location = {
                    'lat': response.location.latitude,
                    'lon': response.location.longitude,
                    'city': response.city.name or 'Unknown'
                }
                domain = resolve_domain(ip)
                print(ip, domain)
                if ip not in ip_locations:
                    ip_locations[ip] = location
                socketio.emit('packet', {'ip': ip, 'location': location, 'domain': domain})

                # Update packet count and emit line data if there's a previous location
                if previous_location:
                    count = update_packet_count(previous_location, location)
                    socketio.emit('line', {
                        'start': previous_location,
                        'end': location,
                        'count': count
                    })
                previous_location = location
        except geoip2.errors.AddressNotFoundError:
            pass

# Serve the HTML UI
@app.route('/')
def index():
    return render_template('index.html')

# Socket.io connection handler
@socketio.on('connect')
def handle_connect():
    print('New client connected')
    socketio.emit('initialData', {'ipLocations': ip_locations, 'packetCounts': packet_counts, 'totalPackets': total_packets})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# Start packet capture in a separate thread
def run_capture():
    capture_thread = threading.Thread(target=lambda: scapy.sniff(prn=packet_callback, store=False))
    capture_thread.daemon = True
    capture_thread.start()

run_capture()

# Run the Flask server
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)