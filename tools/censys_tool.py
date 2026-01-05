import requests
import json
from utils import load_config

def censys_search(query):
    config = load_config()
    token = config.get('censys_api_id') 
    if not token:
        return [{'type': 'Error', 'value': 'Censys Personal Access Token not configured', 'source': 'System'}]

    # Headers for the new Censys Platform API v3
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json"
    }
    
    # The new Censys Platform API v3 endpoint for hosts
    url = f"https://api.platform.censys.io/v3/global/asset/host/{query}"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        resp = response.json()

        # Correctly parse the new v3 response structure
        services = []
        resource = resp.get('result', {}).get('resource', {})
        for service in resource.get('services', []):
            # Use 'transport_protocol' as confirmed by the JSON response
            services.append(f"{service.get('port')}/{service.get('transport_protocol')}")
        
        info = f"Services: {', '.join(services)}"
        
        return [{'type': 'Censys Host', 'value': info, 'source': 'Censys', 'details': resp.get('result', {})}]
    except requests.exceptions.HTTPError as e:
        # The new API might return a more detailed error message in the response body
        try:
            error_details = e.response.json().get('error', str(e))
        except json.JSONDecodeError:
            error_details = str(e)
        return [{'type': 'Error', 'value': f"Censys API Error: {e.response.status_code} - {error_details}", 'source': 'Censys'}]
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'Censys'}]
