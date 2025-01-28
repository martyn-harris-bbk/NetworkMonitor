#!/usr/bin/env python3.6

import threading
import socket
import sqlite3

from flask import Flask, render_template
from flask_socketio import SocketIO
import scapy.all as scapy
import geoip2.database
import geoip2.errors

# ------------------------------------------
#  Flask and SocketIO initialization
# ------------------------------------------
app = Flask(__name__)
socketio = SocketIO(app)

# ------------------------------------------
#  GeoIP setup
# ------------------------------------------
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# ------------------------------------------
#  Global in-memory data
# ------------------------------------------
ip_locations = {}
packet_counts = {}
total_packets = 0
previous_location = None

# ------------------------------------------
#  Database Helpers
# ------------------------------------------

DB_PATH = "packet_data.db"

def init_db():
    """
    Create the necessary tables if they do not exist.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Store each unique IP and its geolocation/domain
    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_locations (
            ip TEXT PRIMARY KEY,
            lat REAL,
            lon REAL,
            city TEXT,
            domain TEXT
        )
    ''')

    # Store lines between locations, with a count of how many packets traveled that route
    c.execute('''
        CREATE TABLE IF NOT EXISTS lines (
            start_lat REAL,
            start_lon REAL,
            end_lat REAL,
            end_lon REAL,
            count INTEGER,
            PRIMARY KEY (start_lat, start_lon, end_lat, end_lon)
        )
    ''')

    # Keep track of total packets in a single row
    c.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY,
            total_packets INTEGER
        )
    ''')

    # Ensure exactly one row in stats table (id=1)
    c.execute("INSERT OR IGNORE INTO stats (id, total_packets) VALUES (1, 0)")

    conn.commit()
    conn.close()

def load_data():
    """
    Load IP locations, lines, and total packet count from the database
    into the global dictionaries/variables.
    """
    global ip_locations, packet_counts, total_packets

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Load IP locations
    c.execute("SELECT ip, lat, lon, city, domain FROM ip_locations")
    for ip, lat, lon, city, domain in c.fetchall():
        ip_locations[ip] = {
            'lat': lat,
            'lon': lon,
            'city': city or 'Unknown'
        }
        # We don't store domain in ip_locations by default, 
        # but you could if you want to reference it later.

    # Load lines (edges between locations)
    c.execute("SELECT start_lat, start_lon, end_lat, end_lon, count FROM lines")
    for s_lat, s_lon, e_lat, e_lon, cnt in c.fetchall():
        key = f"{s_lat},{s_lon}->{e_lat},{e_lon}"
        packet_counts[key] = cnt

    # Load total packets
    c.execute("SELECT total_packets FROM stats WHERE id=1")
    row = c.fetchone()
    if row:
        total_packets = row[0]

    conn.close()

def save_ip_location(ip, lat, lon, city, domain):
    """
    Insert or update an IP's location/domain in the database.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO ip_locations (ip, lat, lon, city, domain)
        VALUES (?, ?, ?, ?, ?)
    ''', (ip, lat, lon, city, domain))
    conn.commit()
    conn.close()

def update_line_count(start_lat, start_lon, end_lat, end_lon, count):
    """
    Insert or update the line (start->end) with the given count in the database.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO lines (start_lat, start_lon, end_lat, end_lon, count)
        VALUES (?, ?, ?, ?, ?)
    ''', (start_lat, start_lon, end_lat, end_lon, count))
    conn.commit()
    conn.close()

def update_total_packets(total):
    """
    Update the total packet count in the database.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE stats SET total_packets = ? WHERE id = 1', (total,))
    conn.commit()
    conn.close()

# ------------------------------------------
#  App / Socket Handlers
# ------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('New client connected')

    # Emit current data so the frontend can plot immediately
    socketio.emit('initialData', {
        'ipLocations': ip_locations,
        'packetCounts': packet_counts,
        'totalPackets': total_packets
    })

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# ------------------------------------------
#  Packet capturing logic
# ------------------------------------------
def resolve_domain(ip):
    """
    Try to perform a reverse DNS lookup to get the domain name for an IP.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def update_packet_count(start, end):
    """
    Update the in-memory and DB count of packets from start->end.
    Returns the new count.
    """
    global total_packets

    key = f"{start['lat']},{start['lon']}->{end['lat']},{end['lon']}"
    packet_counts[key] = packet_counts.get(key, 0) + 1
    total_packets += 1

    # Update DB
    update_line_count(start['lat'], start['lon'], end['lat'], end['lon'], packet_counts[key])
    update_total_packets(total_packets)

    return packet_counts[key]

def packet_callback(packet):
    """
    Callback function for each sniffed packet. Determines the IP, 
    looks up location/domain, updates DB, and emits events.
    """
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

                # If this IP has not been seen before, store it in memory + DB
                if ip not in ip_locations:
                    ip_locations[ip] = location
                    save_ip_location(ip,
                                     location['lat'],
                                     location['lon'],
                                     location['city'],
                                     domain)

                # Emit the new packet to the frontend
                socketio.emit('packet', {
                    'ip': ip,
                    'location': location,
                    'domain': domain
                })

                # If we have a previous location, update counts for line from previous->current
                if previous_location:
                    count = update_packet_count(previous_location, location)
                    socketio.emit('line', {
                        'start': previous_location,
                        'end': location,
                        'count': count
                    })

                previous_location = location

        except geoip2.errors.AddressNotFoundError:
            # This means the IP wasn't found in the GeoLite DB (e.g. private IP)
            pass

# ------------------------------------------
#  Threaded packet capture
# ------------------------------------------
def run_capture():
    capture_thread = threading.Thread(
        target=lambda: scapy.sniff(prn=packet_callback, store=False, filter="ip")
    )
    capture_thread.daemon = True
    capture_thread.start()

# ------------------------------------------
#  Main Entrypoint
# ------------------------------------------
if __name__ == '__main__':
    # 1. Initialize the database (creates tables if they don't exist)
    init_db()

    # 2. Load existing data from the database into memory
    load_data()

    # 3. Start capturing packets in a background thread
    run_capture()

    # 4. Start the Flask + SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000)
