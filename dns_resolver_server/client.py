import socket

def make_dns_request(domain_name, server_address=('127.0.0.1', 53)):
    """
    Sends a DNS request to the specified DNS server and receives the response.

    Args:
        domain_name (str): The domain name to resolve.
        server_address (tuple): A tuple containing the IP address and port number
                                of the DNS server. Default is ('127.0.0.1', 53).

    Returns:
        str: The resolved DNS record value received from the server.
    """
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send the DNS request to the server
        client_socket.sendto(domain_name.encode(), server_address)

        # Receive the response from the server
        response, _ = client_socket.recvfrom(1024)

        # Decode and return the response
        return response.decode()

    except Exception as e:
        print("An error occurred:", e)
        return None

    finally:
        # Close the socket
        client_socket.close()

# Example usage:
if __name__ == "__main__":
    while True:
        domain_name = input("Enter dns: ")  # Replace with the desired domain name
        server_address = ('127.0.0.1', 53)  # Replace with the DNS server address and port
        resolved_record = make_dns_request(domain_name, server_address)
        if resolved_record:
            print(f"Resolved DNS record for {domain_name}: {resolved_record}")
        else:
            print(f"No DNS record found for {domain_name}")
