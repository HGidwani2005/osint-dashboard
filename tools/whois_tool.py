import whois
import datetime

def whois_search(domain):
    try:
        w = whois.whois(domain)
        if not w.get('domain_name'):
            return [{'type': 'Error', 'value': 'WHOIS data not found for domain.', 'source': 'WHOIS'}]

        # Format the result for display in the main table
        info = f"Registrar: {w.registrar}, Created: {w.creation_date}, Expires: {w.expiration_date}"
        
        # The whois object is a dict-like object, but its values can include non-serializable datetime objects.
        # We create a serializable copy.
        details_copy = {}
        for key, value in w.items():
            if isinstance(value, datetime.datetime):
                details_copy[key] = value.isoformat()
            elif isinstance(value, list):
                # Handle lists that might contain datetimes
                details_copy[key] = [v.isoformat() if isinstance(v, datetime.datetime) else v for v in value]
            else:
                details_copy[key] = value

        findings = [{
            'type': 'WHOIS', 
            'value': info, 
            'source': 'WHOIS',
            'details': details_copy
        }]
        return findings
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'WHOIS'}]
