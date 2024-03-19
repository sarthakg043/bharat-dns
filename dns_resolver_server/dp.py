import socket
import dns.resolver

def resolve_dns_udp(server_address=('0.0.0.0', 53)):
    """
    Resolves DNS requests from clients via UDP and sends the response back.

    Args:
        server_address (tuple): A tuple containing the IP address and port number
                                to bind the DNS server. Default is ('0.0.0.0', 53).
    """
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Bind the socket to the server address
        server_socket.bind(server_address)
        print(f"DNS server listening at {server_address[0]}:{server_address[1]}...")

        # Receive and handle DNS requests
        while True:
            data, client_address = server_socket.recvfrom(1024)  # Receive DNS request data
            print(data)
            print(data.decode())
            print(type(data.decode().strip()))
            domain_name = data.decode().strip()  # Decode the domain name from the received data

            # Resolve the DNS request using the resolve_dns function
            resolved_record = resolve_dns(domain_name)

            # If a DNS record is resolved, send the response back to the client
            if resolved_record:
                print(f"Resolved DNS record for {domain_name}: {resolved_record}")
                server_socket.sendto(resolved_record.encode(), client_address)
            else:
                print(f"No DNS record found for {domain_name}")
                server_socket.sendto(b"Record not found", client_address)  # Send error response

    except KeyboardInterrupt:
        print("\nDNS server stopped.")
    finally:
        # Close the socket when done
        server_socket.close()

def resolve_dns(domain_name):
    """
    Resolves a domain name using the system-configured DNS resolver.

    Args:
        domain_name (str): The domain name to resolve.

    Returns:
        str or None: The resolved DNS record value if found, or None if not found.
    """
    resolver = dns.resolver.Resolver()
    # Perform the DNS query
    for q_type in ["CNAME", "A", "AAAA", "SOA", "MX", "NS", "TXT"]:
        try:
            answer = resolver.resolve(domain_name, q_type)
            return str(answer[0])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.Timeout:
            print("DNS resolution timed out.")
            return None
        except dns.exception.DNSException as e:
            print(f"DNS resolution failed: {e}")
            return None

# Example usage:
if __name__ == "__main__":
    resolve_dns_udp()
