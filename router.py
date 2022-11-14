import sys
import socket

router_ip = sys.argv[1]
router_port = int(sys.argv[2])
router_routes = sys.argv[3]

visited = []

# Socket not connection oriented
router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
router_socket.bind((router_ip, router_port))

# Packet parser
# IP_packet = "127.0.0.1,8881,hola"
def parse_packet(IP_packet):
    IP_packet = IP_packet.decode()
    IP_packet = IP_packet.split(",")
    return IP_packet

def create_packet(IP_packet):
    IP_packet = ",".join(IP_packet)
    return IP_packet

# Checks all the routes
# Line format: ip (from port) (until port) (destiny_ip) (destiny_port)
def check_routes(route_file_name, destination_address):
    with open(route_file_name, "r") as route_file:
        for line in route_file:
            line = line.split(" ")
            if line[0] == destination_address[0]:
                if int(line[1]) <= destination_address[1] and int(line[2]) >= destination_address[1]:
                    return (line[3], int(line[4]))
    return None


IP_packet_v1 = "127.0.0.1,8881,hola".encode()
parsed_IP_packet = parse_packet(IP_packet_v1)
IP_packet_v2_str = create_packet(parsed_IP_packet)
IP_packet_v2 = IP_packet_v2_str.encode()
print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))

# check_routes test
print("Check Routes Test 1 ->", check_routes("rutas_R3_v2.txt", ("127.0.0.1", 8882)) == ("127.0.0.1", 8882))
print("Check Routes Test 2 ->", check_routes("rutas_R3_v2.txt", ("127.0.0.1", 8884)) == None)

# Router loop
while True:
    received, client_address = router_socket.recvfrom(1024)
    parsed_IP_packet = parse_packet(received)
    print(parsed_IP_packet)
    destiny_address = (parsed_IP_packet[0], int(parsed_IP_packet[1]))
    destiny_route = check_routes(router_routes, destiny_address)
    if destiny_route != None:
        print(f"Resending packet {parsed_IP_packet} with final destination {destiny_address} from {(router_ip, router_port)} to {destiny_route}")
        router_socket.sendto(received, destiny_route)
    else:
        print(f"No route found for destination address {destiny_address} for packet {parsed_IP_packet}")