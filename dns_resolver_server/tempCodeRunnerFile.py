def create_response(query_name, query_type, data, request):
    response = dns.message.make_response(request)
    response.question = request.question

    if query_type == dns.rdatatype.A:
        try:
            RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, data)
            response.answer.append(RRset)
        except:
            print(f"Error creating A record response for {query_name}")
    elif query_type == dns.rdatatype.AAAA:
        try:
            RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, query_type, data)
            response.answer.append(RRset)
        except:
            print(f"Error creating AAAA record response for {query_name}")
    # Add more conditions for other record types as needed