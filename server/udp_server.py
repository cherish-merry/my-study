import socket

# AF_INET 表示使用IPv4, SOCK_DGRAM 则表明数据将是数据报(datagrams)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

udp.bind(('0.0.0.0', 8888))

while True:
    rec_msg, addr = udp.recvfrom(65535)
    client_ip, client_port = addr
    print('client_ip:', client_ip, 'client_port:', client_port)

    print('msg from client:', rec_msg.decode('utf8'))

    ack_msg = 'Hello, udp client.'
    try:
        udp.sendto(ack_msg.encode('utf8'), addr)
    except:
        print(addr)
