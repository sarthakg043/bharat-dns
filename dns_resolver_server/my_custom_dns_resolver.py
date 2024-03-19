import socket
import struct

def resolve_dns(domain, record_type):
    # Root DNS server IP addresses
    root_servers = ['198.41.0.4', '192.228.79.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', 
                    '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', 
                    '193.0.14.129', '199.7.83.42', '202.12.27.33']

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        for root_server in root_servers:
            # Send DNS query to root DNS server
            sock.sendto(build_dns_query(domain, record_type), (root_server, 53))
            
            # Receive DNS response
            response, _ = sock.recvfrom(1024)
            
            # Parse DNS response
            # (You need to implement DNS response parsing)
            # # parsed_response = parse_dns_response(response)
            
            # Check if the response contains the desired record
            # # if parsed_response:
            #   return parsed_response
            
            return response
                
    finally:
        # Close the socket
        sock.close()

    return None

def build_dns_query(domain, record_type):
    # DNS message format: https://tools.ietf.org/html/rfc1035#section-4.1.1
    message_id = 1234  # Unique identifier for the query
    flags = 0x0100      # Standard query (QR=0), Recursion desired (RD=1)
    qd_count = 1        # Number of questions in the query section
    an_count = 0        # Number of resource records in the answer section
    ns_count = 0        # Number of name server resource records in the authority records section
    ar_count = 0        # Number of resource records in the additional records section
    
    # Create DNS query message
    query = struct.pack('!HHHHHH', message_id, flags, qd_count, an_count, ns_count, ar_count)
    
    # Encode domain name
    labels = domain.split('.')
    for label in labels:
        query += struct.pack('B', len(label))
        query += label.encode('utf-8')
    query += b'\x00'  # Null-terminator for domain name
    
    # Query type and class (IN for Internet)
    query += struct.pack('!HH', record_type, 1)
    
    return query

def parse_dns_response(response):
    # You need to implement DNS response parsing
    # Refer to DNS message format: https://tools.ietf.org/html/rfc1035#section-4.1.1
    # Parse response header, question section, answer section, etc.
    # Extract the desired record from the answer section
    # Return the parsed record (if found) or None
    
    # Parse the header section
    header = response[:12]
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header)

    # Parse the question section
    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = parse_domain_name(response, offset)
        qtype, qclass = struct.unpack('!HH', response[offset:offset+4])
        questions.append({'name': name, 'type': qtype, 'class': qclass})
        offset += 4

    # Parse the answer section
    answers = parse_dns_records(response, offset, ancount)

    # Parse the authority section
    authorities = parse_dns_records(response, offset, nscount)

    # Parse the additional section
    additionals = parse_dns_records(response, offset, arcount)

    return {
        'header': {'id': id, 'flags': flags, 'qdcount': qdcount, 'ancount': ancount, 'nscount': nscount, 'arcount': arcount},
        'questions': questions,
        'answers': answers,
        'authorities': authorities,
        'additionals': additionals
    }
    
def parse_domain_name(response, offset):
    labels = []
    while True:
        length = response[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack('!H', response[offset:offset+2])[0] & 0x3FFF
            name, _ = parse_domain_name(response, pointer)
            return '.'.join(labels) + '.' + name, offset + 2
        else:
            labels.append(response[offset+1:offset+1+length].decode('utf-8'))
            offset += length + 1
    return '.'.join(labels), offset

def parse_dns_records(response, offset, count):
    records = []
    for _ in range(count):
        name, offset = parse_domain_name(response, offset)
        qtype, qclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
        rdata = response[offset+10:offset+10+rdlength]
        records.append({'name': name, 'type': qtype, 'class': qclass, 'ttl': ttl, 'rdata': rdata})
        offset += 10 + rdlength
    return records

def print_dns_response(response):
    # Parse the DNS response
    parsed_response = parse_dns_response(response)

    # Print header
    header = parsed_response['header']
    print(f"Header:")
    print(f"  ID: {header['id']}")
    print(f"  Flags: 0x{header['flags']:04X}")
    print(f"  QDCOUNT: {header['qdcount']}")
    print(f"  ANCOUNT: {header['ancount']}")
    print(f"  NSCOUNT: {header['nscount']}")
    print(f"  ARCOUNT: {header['arcount']}")

    # Print questions
    questions = parsed_response['questions']
    print("\nQuestions:")
    for question in questions:
        print(f"  Name: {question['name']}")
        print(f"  Type: {question['type']}")
        print(f"  Class: {question['class']}")

    # Print answers
    answers = parsed_response['answers']
    print("\nAnswers:")
    for answer in answers:
        print(f"  Name: {answer['name']}")
        print(f"  Type: {answer['type']}")
        print(f"  Class: {answer['class']}")
        print(f"  TTL: {answer['ttl']}")
        print(f"  RDATA: {answer['rdata']}")

    # Print authorities
    authorities = parsed_response['authorities']
    print("\nAuthorities:")
    for authority in authorities:
        print(f"  Name: {authority['name']}")
        print(f"  Type: {authority['type']}")
        print(f"  Class: {authority['class']}")
        print(f"  TTL: {authority['ttl']}")
        print(f"  RDATA: {authority['rdata']}")

    # Print additionals
    additionals = parsed_response['additionals']
    print("\nAdditionals:")
    for additional in additionals:
        print(f"  Name: {additional['name']}")
        print(f"  Type: {additional['type']}")
        print(f"  Class: {additional['class']}")
        print(f"  TTL: {additional['ttl']}")
        print(f"  RDATA: {additional['rdata']}")

def get_ip_from_dns_response(response):
    # Parse the DNS response
    parsed_response = parse_dns_response(response)

    # Iterate through the answers
    for answer in parsed_response['answers']:
        # Check if the answer is of type A (IPv4 address)
        if answer['type'] == 1:  # A record type
            # Extract the IP address from the RDATA field
            ip_address = socket.inet_ntoa(answer['rdata'])
            return ip_address

    # If no A record is found, return None
    return None


# Example usage
if __name__ == "__main__":
    domain = 'google.com'
    record_type = 1  # A record
    result = resolve_dns(domain, record_type)
    if result:
        ip_address = get_ip_from_dns_response(result)
        if ip_address:
            print(f"IP Address for {domain}: {ip_address}")
        else:
            print(f"No A record found for {domain}")
    else:
        print(f"Failed to resolve DNS for {domain}")
