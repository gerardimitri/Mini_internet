import sys
import socket

router_ip = sys.argv[1]
router_port = int(sys.argv[2])
router_routes = sys.argv[3]

visited = []
visited_max_size = 0

# Socket not connection oriented
router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
router_socket.bind((router_ip, router_port))

# Packet parser
# IP_packet = "127.0.0.1,8881,TTL,hola"
def parse_packet(IP_packet):
    IP_packet = IP_packet.decode()
    IP_packet = IP_packet.split(",")
    return IP_packet

def create_packet(IP_packet):
    IP_packet = ",".join(IP_packet)
    return IP_packet

def get_visited_size(route_file_name, destination_address):
    global visited_max_size
    visited_max_size = 0
    with open(route_file_name, "r") as route_file:
        for line in route_file:
            line = line.split(" ")
            if line[0] == destination_address[0]:
                if int(line[1]) <= destination_address[1] and int(line[2]) >= destination_address[1]:
                    visited_max_size += 1
    return visited_max_size

def check_visited_size():
    global visited_max_size
    global visited
    if len(visited) >= visited_max_size:
        visited = []

# Checks all the routes
# Line format: ip (from port) (until port) (destiny_ip) (destiny_port)
def check_routes(route_file_name, destination_address):
    global visited
    with open(route_file_name, "r") as route_file:
        for line in route_file:
            line = line.split(" ")
            if line[0] == destination_address[0]:
                if int(line[1]) <= destination_address[1] and int(line[2]) >= destination_address[1]:
                    check_visited_size()
                    print("Route found")
                    if (line[3], int(line[4])) in visited:
                        continue
                    else:
                        visited.append((line[3], int(line[4])))
                        return (line[3], int(line[4]))
    return None

IP_packet_v1 = "127.0.0.1,8881,4,hola".encode()
parsed_IP_packet = parse_packet(IP_packet_v1)
IP_packet_v2_str = create_packet(parsed_IP_packet)
IP_packet_v2 = IP_packet_v2_str.encode()
print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

# Router loop
while True:
    received, client_address = router_socket.recvfrom(1024)
    parsed_IP_packet = parse_packet(received)
    TTL = int(parsed_IP_packet[2])
    if TTL > 0:
        destiny_address = (parsed_IP_packet[0], int(parsed_IP_packet[1]))
        visited_max_size = get_visited_size(router_routes, destiny_address)
        destiny_route = check_routes(router_routes, destiny_address)
        if destiny_route != None:
            print(f"Resending packet {parsed_IP_packet} with final destination {destiny_address} from {(router_ip, router_port)} to {destiny_route}")
            parsed_IP_packet[2] = str(TTL - 1)
            message_to_send = create_packet(parsed_IP_packet).encode()
            router_socket.sendto(message_to_send, destiny_route)
        else:
            print(f"No route found for destination address {destiny_address} for packet {parsed_IP_packet}")
    else:
        print(f"received package {parsed_IP_packet} with TTL = 0")