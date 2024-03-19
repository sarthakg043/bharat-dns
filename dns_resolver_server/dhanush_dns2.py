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
import mysql.connector
# importing blacklist data domains
bl_df= pd.read_csv("blacklist.csv",usecols=['domain'])
wl_df= pd.read_csv("whitelist.csv",usecols=['domain'])

connection = mysql.connector.connect(host='localhost',
                                         database='dns2',
                                         user='root',
                                         password='kasganj234')



cursor = connection.cursor()


def insert_data(query_name, client_address, time):

    # create_table_query = """
    # CREATE TABLE testdns3 (
    #     query_name VARCHAR(100) PRIMARY KEY ,
    #     client_address VARCHAR(100) ,
    #     time DATETIME
    # )
    # """

    # Execute the query
    # cursor.execute(create_table_query)

    insert_data_query = """
        INSERT INTO testdns3 (query_name, client_address, time) VALUES
        (%s, %s, %s)
        """
    
    query_name_str = str(query_name)
    client_address_str = str(client_address)
    data = (query_name_str, client_address_str, time)
    cursor.execute(insert_data_query, data)

    print("Data sent")



def extract_domain(url):
    # Use tldextract to extract the domain
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    return domain

bl_domains = bl_df['domain'].apply(extract_domain)
wl_domains = wl_df['domain'].apply(extract_domain)


def get_ip_address(query_name):
    print(query_name)
    try:
        response = dns_to_ip(query_name)
        return response
    except DNSException as e:
        print(f"DNS resolution failed: {e}")
        return None

def handle_dns_request(request, client_address):
    query_name = str(request.question[0].name)
    query_type = request.question[0].rdtype
    received_domain = extract_domain(query_name)
    received_domain =  received_domain[:-1] 
    received_domain = extract_domain(query_name)    

    if received_domain in wl_domains.values:
        print(f"The domain {received_domain} is whitelisted. Proceed with DNS resolution.")
        response = dns.message.make_response(request)
        response.question = request.question

        if query_type == A:
            
            ip_address = get_ip_address(received_domain)
            if ip_address:
                try:
                    RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, ip_address)
                except:
                    RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
                response.answer.append(RRset)

    elif received_domain in bl_domains.values:
        print(f"The domain {received_domain} is present in the blacklist file.")
        print(f"Blocked {received_domain}")
        # Implement your response for blacklisted domains (e.g., return an error response)
        try:
            response = dns.message.make_response(request)
            response.question = request.question
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
        server_address = ('172.16.202.228', 5050)
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
            response = dns.message.make_response(request)
            response.question = request.question

            if query_type == A:
                
                ip_address = get_ip_address(received_domain)
                if ip_address:
                    try:
                        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, ip_address)
                    except:
                        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, "0.0.0.0")
                    response.answer.append(RRset)

    # Set the query ID of the response message
    response.id = request.id
    print(f"Request of {query_name} sent back to {client_address} at time {datetime.now()}")
    server_socket.sendto(response.to_wire(), client_address)

    insert_data(query_name, client_address, datetime.now())
    
    

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
    server_address = ('172.16.202.228', 53)
    server_socket.bind(server_address)
    
    print("Server listening at{}:{}...".format(*server_address))
    start_dns_server()