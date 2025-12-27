import shodan
from utils import load_config

def shodan_search(query):
    config = load_config()
    api_key = config.get('shodan_api_key')
    if not api_key:
        return [{'type': 'Error', 'value': 'Shodan API key not configured', 'source': 'System'}]
    
    try:
        api = shodan.Shodan(api_key)
        host = api.host(query)
        
        # Data Enrichment for table view
        asn_info = host.get('asn', 'N/A')
        country_name = host.get('country_name', 'N/A')
        ports = ', '.join(str(p) for p in host.get('ports', []))
        
        # Create a more descriptive value for the main table
        hostnames = ', '.join(host.get('hostnames', []))
        value_summary = f"{host.get('ip_str')} | Hostnames: {hostnames}"

        findings = [{
            'type': 'IP',
            'value': value_summary,
            'source': 'Shodan',
            'lat': host.get('latitude'),
            'lon': host.get('longitude'),
            'asn': asn_info,
            'country': country_name,
            'ports': ports,
            'details': host # Add the full host object for the details view
        }]
        return findings
    except shodan.APIError as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'Shodan'}]
