import subprocess

def resolve_dns_with_nslookup(hostname, record_type='A'):
    try:
        command = ['nslookup', hostname]
        if record_type != 'A':
            command.extend(['-type=' + record_type])
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def resolve_dns_with_dig(hostname, record_type='A'):
    try:
        command = ['dig', '+short', hostname]
        if record_type != 'A':
            command.extend([record_type, '+short'])
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def main():
    hostname = input("Enter hostname: ")
    record_type = input("Enter record type (A, AAAA, MX, TXT, etc.): ")
    
    # Resolve DNS with nslookup
    nslookup_result = resolve_dns_with_nslookup(hostname, record_type)
    print("NSLOOKUP RESULT:")
    print(nslookup_result)
    
    # Resolve DNS with dig
    dig_result = resolve_dns_with_dig(hostname, record_type)
    print("DIG RESULT:")
    print(dig_result)

if __name__ == "__main__":
    main()
