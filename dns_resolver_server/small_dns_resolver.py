import dns.resolver

resolver = dns.resolver.Resolver()
print(resolver.nameservers)


def resolve_a_record(domain):
    try:
        response = resolver.resolve(domain, 'A')
        ip_address = response[0].address
        return ip_address
    except dns.resolver.NoAnswer:
        print(f"No A record found for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist")
        return None
    except dns.exception.Timeout:
        print("DNS resolution timeout")
        return None
    except Exception as e:
        print(f"An error occurred during A record resolution: {e}")
        return None

def resolve_aaaa_record(domain):
    try:
        response = resolver.resolve(domain, 'AAAA')
        ipv6_address = response[0].address
        return ipv6_address
    except dns.resolver.NoAnswer:
        print(f"No AAAA record found for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist")
        return None
    except dns.exception.Timeout:
        print("DNS resolution timeout")
        return None
    except Exception as e:
        print(f"An error occurred during AAAA record resolution: {e}")
        return None

def resolve_cname_record(domain):
    try:
        response = resolver.resolve(domain, 'CNAME')
        canonical_name = response[0].target.to_text()
        return canonical_name
    except dns.resolver.NoAnswer:
        print(f"No CNAME record found for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist")
        return None
    except dns.exception.Timeout:
        print("DNS resolution timeout")
        return None
    except Exception as e:
        print(f"An error occurred during CNAME record resolution: {e}")
        return None

def resolve_mx_record(domain):
    try:
        response = resolver.resolve(domain, 'MX')
        mx_records = [(mx.exchange.to_text(), mx.preference) for mx in response]
        return mx_records
    except dns.resolver.NoAnswer:
        print(f"No MX record found for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist")
        return None
    except dns.exception.Timeout:
        print("DNS resolution timeout")
        return None
    except Exception as e:
        print(f"An error occurred during MX record resolution: {e}")
        return None

def resolve_ns_records(domain):
    try:
        response = resolver.resolve(domain, 'NS')
        ns_records = [ns.target.to_text() for ns in response]
        return ns_records
    except dns.resolver.NoAnswer:
        print(f"No NS records found for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist")
        return None
    except dns.exception.Timeout:
        print("DNS resolution timeout")
        return None
    except Exception as e:
        print(f"An error occurred during NS record resolution: {e}")
        return None
    
def resolve_soa_record(domain):
    try:
        response = resolver.resolve(domain, 'SOA')
        soa_record = response[0]
        primary_ns = soa_record.mname.to_text()  # Primary name server
        admin_email = soa_record.rname.to_text()  # Email of the domain administrator
        serial = soa_record.serial  # Serial number
        refresh = soa_record.refresh  # Refresh interval
        retry = soa_record.retry  # Retry interval
        expire = soa_record.expire  # Expire interval
        minimum_ttl = soa_record.minimum  # Minimum TTL
        return primary_ns, admin_email, serial, refresh, retry, expire, minimum_ttl
    except dns.resolver.NoAnswer:
        print(f"No SOA record found for {domain}")
        return None, None, None, None, None, None, None
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist")
        return None, None, None, None, None, None, None
    except dns.exception.Timeout:
        print("DNS resolution timeout")
        return None, None, None, None, None, None, None
    except Exception as e:
        print(f"An error occurred during SOA record resolution: {e}")
        return None, None, None, None, None, None, None

# Example usage
domain = 'isro.gov.in'
ip_address = resolve_a_record(domain)
if ip_address:
    print(f"The IP address of {domain} is {ip_address}")

# for AAAA record
ipv6_address = resolve_aaaa_record(domain)
if ipv6_address:
    print(f"The IPv6 address of {domain} is {ipv6_address}")
    
# for CNAME record
canonical_name = resolve_cname_record(domain)
if canonical_name:
    print(f"The canonical name for {domain} is {canonical_name}")
  
# for Mail Exchange MX records  
mx_records = resolve_mx_record(domain)
if mx_records:
    print(f"The MX records for {domain} are:")
    for mx_record in mx_records:
        print(f"  {mx_record[0]} (Preference: {mx_record[1]})")
        
authority_servers = resolve_ns_records(domain)
if authority_servers:
    print(f"The authoritative name servers for {domain} are:")
    for server in authority_servers:
        print(f"  {server}")

# for SOA records      
primary_ns, admin_email, serial, refresh, retry, expire, minimum_ttl = resolve_soa_record(domain)
if primary_ns:
    print(f"The SOA record for {domain} is:")
    print(f"  Primary Name Server: {primary_ns}")
    print(f"  Administrator Email: {admin_email}")
    print(f"  Serial Number: {serial}")
    print(f"  Refresh Interval: {refresh}")
    print(f"  Retry Interval: {retry}")
    print(f"  Expire Interval: {expire}")
    print(f"  Minimum TTL: {minimum_ttl}")
    