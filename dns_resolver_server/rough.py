import dns.resolver
import dns.message
import dns.query
import dns.rdatatype

def resolve(name):
    nameserver = "198.41.0.4"

    while True:
        # Prepare a message asking for an A record (an IP address) for `name`
        m = dns.message.make_query(name, dns.rdatatype.A)

        # Send the DNS request to the IP in `nameserver`
        print("Asking {} about {}".format(nameserver, name))
        try:
            resp = dns.query.udp(m, nameserver, timeout=5)
        except dns.exception.Timeout:
            return None, "DNS query timeout"

        # If an ANSWER SECTION exists, we're done
        if resp.answer:
            return resp.answer, None

        # If an ADDITIONAL SECTION exists, look in it for an A record for the
        # next-level nameserver. If one doesn't exist, we have to error out
        found = False
        for rrset in resp.additional:
            for rr in rrset:
                if rr.rdtype == dns.rdatatype.A:
                    nameserver = rr.items[0].address
                    found = True
                    break
            if found:
                break
        if not found:
            return None, "Break in the chain"

        # ... and recurse!

# Example usage:
name = "m.com"
records, error = resolve(name)
if records:
    print("Resolved records for {}: {}".format(name, records))
else:
    print("Failed to resolve {}: {}".format(name, error))
