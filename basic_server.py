import socket

HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Non-privileged port

def start_server():
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # bind to given IP and port
        server_socket.bind((HOST, PORT))

        # start listening for connection requests
        server_socket.listen()
        print(f"Echo server listening on {HOST}:{PORT}...")

        # when a connection arrives, accept it and return details (accept blocks until connection arrives) 
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")

            # read / receive data through the connection (recv blocks until data received or connection closed)
            data = conn.recv(1024)

            # if data has been received
            if data:
                print(f"Received from client: {data.decode('utf-8')}")
                
                # Send the exact same data back
                conn.sendall(data)
                print("Echoed message back to client.")

if __name__ == '__main__':
    start_server()