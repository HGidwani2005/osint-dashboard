from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils import load_config

def google_dorks_search(query):
    config = load_config()
    api_key = config.get('google_api_key')
    cse_id = config.get('google_cse_id')

    if not api_key or not cse_id:
        return [{'type': 'Error', 'value': 'Google API key or CSE ID not configured', 'source': 'System'}]

    try:
        service = build("customsearch", "v1", developerKey=api_key)
        res = service.cse().list(q=query, cx=cse_id, num=10).execute()
        
        items = res.get('items', [])
        item_count = len(items)
        
        summary_value = f"Found {item_count} results for dork query"
        
        findings = [{
            'type': 'Google Dork',
            'value': summary_value,
            'source': 'Google Dorks',
            'details': res # The full API response
        }]
        return findings
    except HttpError as e:
        return [{'type': 'Error', 'value': f"Google API Error: {e.reason}", 'source': 'Google Dorks'}]
    except Exception as e:
        return [{'type': 'Error', 'value': str(e), 'source': 'Google Dorks'}]
