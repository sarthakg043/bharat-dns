from dns_resolver_server.paralleldns import *
# from dns_resolver_server import dns2

from ml_model_server.dns_tunneling_model import *

def handle_dns_request(request, client_address):
    query_name = str(request.question[0].name)
    query_type = request.question[0].rdtype
    received_domain = extract_domain(query_name)

    if received_domain in get_whitelisted_domains():
        print(f"The domain {received_domain} is whitelisted. Proceed with DNS resolution.")
        response = dns.message.make_response(request)
        response.question = request.question

        if query_type == A:
            ip_address = get_ip_address(received_domain)
            if ip_address:
                try:
                    RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, ip_address)
                    response.answer.append(RRset)
                except:
                    print(f"Error creating response for {received_domain}")

    elif received_domain in get_blacklisted_domains():
        print(f"The domain {received_domain} is present in the blacklist file. Blocked.")
        response = dns.message.make_response(request)
        response.question = request.question
        try:
            RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
            response.answer.append(RRset)
        except:
            print("Error creating response for blacklisted domain")
    else:
        print(f"The domain {received_domain} is not blacklisted. Proceed with DNS resolution.")

        # Implement code for ML model

        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the ML server's address and port
        server_address = ('0.0.0.0', 5050)
        client_socket.connect(server_address)
        print('Connected to {}:{}'.format(*server_address))

        try:
            # Send a string to the server
            message_to_send = query_name
            client_socket.sendall(message_to_send.encode('utf-8'))
            print('Sent string: {!r}'.format(message_to_send))

            # Receive the serialized data (tuple) from the server
            serialized_data = client_socket.recv(4096)

            # Deserialize the data using pickle
            try:
                received_t = pickle.loads(serialized_data)
                print('Received data: {!r}'.format(received_t))
            except:
                received_t = 1
                print('ML not able to detect hence assuming it to be malicious...')

        finally:
            # Clean up the connection
            client_socket.close()
        if(received_t == 1):
            print("ML Model predicted malicious with probability", received_t)
            print(f"Blocked {received_domain}")
            # Implement code for dummy response
            try:
                response = dns.message.make_response(request)
                response.question = request.question
                RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
                response.answer.append(RRset)
            except:
                print("Not Resolved, dummy ip sent!")
        
        else:
            # Process DNS query asynchronously
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(resolve_dns_query, received_domain)
                ip_address = future.result()

            if ip_address:
                response = dns.message.make_response(request)
                response.question = request.question
                try:
                    RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, ip_address)
                    response.answer.append(RRset)
                except:
                    print(f"Error creating response for {received_domain}")

    response.id = request.id
    print(f"Request for {query_name} sent back to {client_address} at {datetime.now()}")
    server_socket.sendto(response.to_wire(), client_address)



server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('0.0.0.0', 53)
server_socket.bind(server_address) 
print(f"Server listening at {server_address}...")
start_dns_server()