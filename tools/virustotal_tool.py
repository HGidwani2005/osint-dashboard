import requests
import re
from base64 import urlsafe_b64encode
from utils import load_config

def virustotal_search(query):
    config = load_config()
    api_key = config.get('virustotal_api_key')
    if not api_key:
        return [{'type': 'Error', 'value': 'VirusTotal API key not configured', 'source': 'System'}]

    headers = {
        "x-apikey": api_key
    }
    
    try:
        # Check if query is an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
            response = requests.get(url, headers=headers)
            response.raise_for_status() # Raise an exception for bad status codes
            resp = response.json()
            
            stats = resp.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            info = f"Malicious: {stats.get('malicious', 0)}, Harmless: {stats.get('harmless', 0)}, Suspicious: {stats.get('suspicious', 0)}"
            return [{'type': 'IP Reputation', 'value': info, 'source': 'VirusTotal', 'details': resp}]
        else: # Assume it's a domain/URL
            url_id = urlsafe_b64encode(query.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            resp = response.json()

            stats = resp.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            info = f"Malicious: {stats.get('malicious', 0)}, Harmless: {stats.get('harmless', 0)}, Suspicious: {stats.get('suspicious', 0)}"
            return [{'type': 'Domain Reputation', 'value': info, 'source': 'VirusTotal', 'details': resp}]
    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors (like 404 Not Found) gracefully
        return [{'type': 'Error', 'value': f"VirusTotal API Error: {e.response.status_code} {e.response.reason}", 'source': 'VirusTotal'}]
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'VirusTotal'}]
