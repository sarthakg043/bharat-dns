import requests

# AlienVault OTX API endpoint for TAXII server
TAXII_SERVER_URL = 'https://otx.alienvault.com/api/v1/taxii/stix2'

# Your AlienVault OTX API key
API_KEY = '3ed46b05dc8adabc9059edc429c3f9dd0af305766ed8d251fa822fb66613a38c'

def fetch_malicious_dns_data():
    headers = {
        'X-OTX-API-KEY': API_KEY,
        'Accept': 'application/taxii+json'
    }

    # Construct TAXII query message
    # Here, we're querying for malicious DNS data
    query = {
        "type": "identity",
        "filters": [{
            "type": "custom",
            "field": "type",
            "value": "indicator",
            "operator": "equals"
        }, {
            "type": "custom",
            "field": "indicator",
            "value": "dns",
            "operator": "contains"
        }]
    }

    try:
        # Send POST request to TAXII server
        response = requests.post(TAXII_SERVER_URL, headers=headers, json=query)
        response.raise_for_status()  # Raise exception for any HTTP error

        # Parse response JSON
        data = response.json()

        # Extract malicious DNS data
        malicious_dns_data = [indicator['id'] for indicator in data.get('objects', [])]

        return malicious_dns_data

    except requests.RequestException as e:
        print(f"Error fetching malicious DNS data: {e}")
        return None

# Example usage
if __name__ == "__main__":
    malicious_dns_data = fetch_malicious_dns_data()
    if malicious_dns_data:
        print("Malicious DNS data:")
        for dns_indicator in malicious_dns_data:
            print(dns_indicator)
    else:
        print("Failed to fetch malicious DNS data.")
