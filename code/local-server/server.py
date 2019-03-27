import socket
import pyte
import hpfeeds
import datetime
from collections import defaultdict
import json
import uuid
import hashlib

POT_IP = 'YOUR IP'
HOST_NAME = 'HOST_NAME'
LOCATION = 'LOCATION'
ARCH = 'YOUR ARCH'
SERVER_IP = 'SERVER IP'
SERVER_PORT = 1000
HP_USERNAME = 'USERNAME'
HP_PASSWORD = 'PASSWORD'
HP_SESSION = 'SESSION_ID'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 5000))

sessions = defaultdict(dict)

class HpfeedsCon():
    def __init__(self, ip, port, ident, secret, channel):
        self.hpfeeds_ip = ip
        self.hpfeeds_port = port
        self.ident = ident
        self.secret = secret
        self.channel = channel
        self.hpc = None

    def connect(self):
        try: 
            self.hpc = hpfeeds.new(self.hpfeeds_ip, self.hpfeeds_port, self.ident, self.secret)
        except hpfeeds.FeedException as e:
            error = 'Connect Hpfeeds Sever Error: {0}'.format(e)
            print(error)

    def send(self, data):
        self.hpc.publish(self.channel, data)
        emsg = self.hpc.wait()
        if emsg: 
            error = 'Got Error From Hpfeeds Sever:' + emsg
            print(error)

    def close(self):
        self.hpc.close()

def send_content(data):
  data = data.encode('utf-8')
  hpfeedConn = HpfeedsCon(SERVER_IP, SERVER_PORT, HP_USERNAME, HP_PASSWORD, HP_SESSION)
  hpfeedConn.connect()
  hpfeedConn.send(data)
  hpfeedConn.close()
  return hashlib.sha256(data).hexdigest()

def send(raw_data, sha256, svr_type):
  pub_data = {
    'session': HOST_NAME + '-' + str(uuid.uuid1()).replace('-', ''),
    'hpHostName': HOST_NAME,
    'hpLocation': LOCATION,
    'hpSvrType': svr_type,
    'mainInfo': raw_data,
    'architechture': ARCH,
    'filesha256': sha256
  }
  json_data = json.dumps(pub_data)
  hpfeedConn = HpfeedsCon(SERVER_IP, SERVER_PORT, HP_USERNAME, HP_PASSWORD, HP_SESSION)
  hpfeedConn.connect()
  hpfeedConn.send(json_data)
  hpfeedConn.close()

def bytes2hexString(input):
  return ''.join('{:02X}'.format(x) for x in input)

def netBytes2Short(input):
  if len(input) != 2:
    raise Exception('Invalid input')
  return (input[0] * 256) + input[1]

def get_session_id(data):
  return bytes2hexString(data[2:18])

def process_ssh(data):
  msg_type = data[1]
  sid = get_session_id(data)
  msg = data[18:]
  session = sessions[sid]
  if msg_type == 0x00: # connection
    ip = '.'.join(str(i) for i in msg[:4])
    port = msg[4] * 256 + msg[5]
    session['data'] = {
      'sessionID': sid,
      'svrType': 'ssh',
      'potIP': POT_IP,
      'portPort': 22,
      'attackIP': ip,
      'attackPort': port,
      'blastList': [],
      'execCommands': [],
      'startTime': datetime.datetime.now().isoformat(),
      'resize': 0,
      'strokes': []
    }
  elif msg_type == 0x01: # login
    username_len = msg[0]
    username = str(msg[1:username_len + 1])
    password_len = msg[username_len + 1]
    password = str(msg[username_len + 2:])
    session['data']['blastList'].append('%s::%s' % (username, password))
  elif msg_type == 0x02: # session
    pair = session['data']['blastList'][-1].split('::')
    session['data']['loginName'] = pair[0]
    session['data']['loginPasswd'] = pair[1]
    screen = pyte.HistoryScreen(80, 24, history=1000, ratio=1)
    stream = pyte.ByteStream(screen)
    session['screen'] = screen
    session['stream'] = stream
  elif msg_type == 0x03: # window resize
    r = msg[0]
    c = msg[1]
    session['screen'].resize(r, c)
    session['data']['resize'] += 1
  elif msg_type == 0x04: # data message
    session['stream'].feed(msg)
    session['data']['strokes'].append(msg)
  elif msg_type == 0x05: # disconnection
    session['data']['endTime'] = datetime.datetime.now().isoformat()
    if 'screen' in session:
      screen = session['screen']
      while screen.history.position > screen.lines and screen.history.top:
        screen.prev_page()
      data = ''
      rest_lines = 0
      while screen.history.position < screen.history.size and screen.history.bottom:
        data += '\n'.join(screen.display) + '\n'
        rest_lines = len(screen.history.bottom)
        screen.next_page()
      data += '\n'.join(screen.display[-rest_lines:]) + '\n'
    sha256 = send_content(data)
    send(session['data'], sha256, 'ssh')
    del sessions[sid]

def process_telnet(data):
  msg_type = data[1]
  sid = get_session_id(data)
  msg = data[18:]
  session = sessions[sid]
  if msg_type == 0x00: # connection
    ip = '.'.join(str(i) for i in msg[:4])
    port = msg[4] * 256 + msg[5]
    session['data'] = {
      'sessionID': sid,
      'svrType': 'telnet',
      'potIP': POT_IP,
      'portPort': 23,
      'attackIP': ip,
      'attackPort': port,
      'blastList': [],
      'execCommands': [],
      'startTime': datetime.datetime.now().isoformat(),
      'resize': 0,
      'strokes': []
    }
  elif msg_type == 0x01: # login
    username_len = msg[0]
    username = str(msg[1:username_len + 1])
    password_len = msg[username_len + 1]
    password = str(msg[username_len + 2:])
    session['data']['blastList'].append('%s::%s' % (username, password))
  elif msg_type == 0x02: # session
    pair = session['data']['blastList'][-1].split('::')
    session['data']['loginName'] = pair[0]
    session['data']['loginPasswd'] = pair[1]
    screen = pyte.HistoryScreen(80, 24, history=1000, ratio=1)
    stream = pyte.ByteStream(screen)
    session['screen'] = screen
    session['stream'] = stream
  elif msg_type == 0x04: # data message
    session['stream'].feed(msg)
    session['data']['strokes'].append(msg)
  elif msg_type == 0x05: # disconnection
    session['data']['endTime'] = datetime.datetime.now().isoformat()
    if 'screen' in session:
      screen = session['screen']
      while screen.history.position > screen.lines and screen.history.top:
        screen.prev_page()
      data = ''
      rest_lines = 0
      while screen.history.position < screen.history.size and screen.history.bottom:
        data += '\n'.join(screen.display) + '\n'
        rest_lines = len(screen.history.bottom)
        screen.next_page()
      data += '\n'.join(screen.display[-rest_lines:]) + '\n'
    sha256 = send_content(data)
    send(session['data'], sha256, 'telnet')
    del sessions[sid]

def process_cpu(data):
  usage = int(data[1:])
  send({
    'svrType': 'cpu',
    'potIP': POT_IP,
    'usage': usage
  }, '', 'cpu')

def process_processes(data):
  processes = str(data[1:])
  send({
    'svrType': 'process',
    'potIP': POT_IP,
    'process': processes
  }, '', 'process')

while True:
    data, addr = sock.recvfrom(65535)
    data = bytearray(data)
    if data[0] == 0x00:
      try:
        process_ssh(data)
      except Exception as ex:
        print(ex)
    if data[1] == 0x01:
      try:
        process_telnet(data)
      except Exception as ex:
        print(ex)
    if data[0] == 0x10:
      try:
        process_cpu(data)
      except Exception as ex:
        print(ex)
    if data[0] == 0x11:
      try:
        process_processes(data)
      except Exception as ex:
        print(ex)
