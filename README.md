# OSINT Threat Intelligence Dashboard

A professional web-based dashboard for collecting, visualizing, and exporting OSINT (Open-Source Intelligence) data. Features an interactive UI with dark mode, real-time search, and modern design.

## Features
- Collect OSINT data using simulated tools (Shodan, theHarvester, Google Dorks).
- Interactive search with real-time filtering and sortable table.
- Geolocation heatmap for IPs.
- Export findings to PDF.
- Dark mode toggle and responsive design.

## Installation
1. Clone the repo: `git clone https://github.com/yourusername/osint-dashboard.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Install wkhtmltopdf for PDF export (see below).
4. Run: `python app.py`
5. Open http://127.0.0.1:5000/

## wkhtmltopdf Installation
- **Ubuntu/Debian**: `sudo apt-get install wkhtmltopdf`
- **macOS**: `brew install wkhtmltopdf`
- **Windows**: Download from [wkhtmltopdf.org](https://wkhtmltopdf.org/downloads.html)

## Usage
- Pre-loaded sample data for immediate testing.
- Use the sidebar to navigate sections.
- Collect data, search, view heatmap, and export.

## Notes
- Demo with mocked OSINT tools. Integrate real APIs for production.
- Ensure ethical OSINT practices.
