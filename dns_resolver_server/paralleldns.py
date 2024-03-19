import dns.message
import dns.query
import dns.resolver
import dns.zone
from dns.exception import DNSException
from dns.rdatatype import *
import socket
import pickle
from sg_ip import dns_to_ip
import tldextract
import pandas as pd
from datetime import datetime


print("Resolver nameservers: ", end="")
resolver = dns.resolver.Resolver()
print(resolver.nameservers, "\n")

# importing blacklist data domains
bl_df= pd.read_csv("blacklist.csv",usecols=['domain'])
wl_df= pd.read_csv("whitelist.csv",usecols=['domain'])


def extract_domain(url):
    # Use tldextract to extract the domain
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    return domain

bl_domains = bl_df['domain'].apply(extract_domain)
wl_domains = wl_df['domain'].apply(extract_domain)

## Make a function to create response

def resolve_dns(domain_name):
    print("resolve_dns: ", domain_name)
    """
    Resolves a domain name using the system-configured DNS resolver.

    Args:
        domain_name (str): The domain name to resolve.

    Returns:
        str or None: The resolved DNS record value if found, or None if not found.
    """
    # Perform the DNS query
    for q_type in ["CNAME", "A", "AAAA", "SOA", "MX", "NS", "TXT"]:
        try:
            answer = resolver.resolve(domain_name, q_type)
            return (str(answer[0]), q_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.Timeout:
            print("DNS resolution timed out.")
            return None
        except dns.exception.DNSException as e:
            print(f"DNS resolution failed: {e}")
            return None

def handle_dns_record_type(resp, query_name):
    """_summary_
    Please create the following parts of response prior to passing as argument
        response = dns.message.make_response(request)
        response.question = request.question
    Args:
        resp (_type_): _description_
        query_name (_type_): _description_

    Returns:
        _type_: _description_
    """
    response = resp
    try:
        ip_addresses = resolve_dns(query_name)
        query_type = ip_addresses[1]
    except TypeError:
        print(f"Could not resolve {query_name}.")
        ip_addresses = ("0.0.0.0", "A")
        query_type = ip_addresses[1]
        
    if query_type == "CNAME":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.CNAME, ip_addresses[0])
        response.answer.append(RRset)
        print("CNAME")
        response = handle_dns_record_type(response, ip_addresses[0])
    if query_type == "MX":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.MX, ip_addresses[0])
        response.answer.append(RRset)
    if query_type == "A":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.A, ip_addresses[0])
        response.answer.append(RRset)
    if query_type == "AAAA":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.AAAA, ip_addresses[0])
        response.answer.append(RRset)
    if query_type == "SOA":  # Handling SOA record type
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.SOA, ip_addresses[0])
        response.authority.append(RRset)
    # Add more record types as needed
    
    return response

def handle_dns_request(request, client_address):
    query_name = str(request.question[0].name)
    print("Query Name: ",query_name, type(query_name))
    query_type = request.question[0].rdtype
    received_domain = extract_domain(query_name)
    received_domain =  received_domain[:-1] 
    received_domain = extract_domain(query_name)
    response = dns.message.make_response(request)
    response.question = request.question 
    
    if received_domain in wl_domains.values:
        print(f"The domain {received_domain} is whitelisted. Proceed with DNS resolution.")
        # Resolve DNS
        response = handle_dns_record_type(response, query_name)

    elif received_domain in bl_domains.values:
        print(f"The domain {received_domain} is present in the blacklist file.")
        print(f"Blocked {received_domain}")
        # Implement your response for blacklisted domains (e.g., return an error response)
        try:
            RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
            response.answer.append(RRset)
        except:
            print("Not Resolved, dummy ip sent!")
    else:
        # Implement your DNS processing logic here
        # For demonstration, just print a success message
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
            print(f"Blocked {query_name}")
            # Implement code for dummy response
            try:
                RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
                response.answer.append(RRset)
            except:
                print("Not Resolved, dummy ip sent!")
        else:            
            response = handle_dns_record_type(response, query_name)
            
    # Set the query ID of the response message
    response.id = request.id
    print(f"Request of {query_name} is sent back to {client_address} at time {datetime.now()}")
    server_socket.sendto(response.to_wire(), client_address)

def start_dns_server():
    
    while True:
        try:
            data, client_address = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            
            handle_dns_request(request, client_address)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', 53)
    server_socket.bind(server_address)
    
    print("Server listening at{}:{}...".format(*server_address))
    start_dns_server()