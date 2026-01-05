import subprocess
import sys
import os

def sherlock_search(username):
    try:
        # Add --no-color to prevent ANSI escape codes in the output
        # Add a timeout and run from the user's home directory for consistency
        command = [sys.executable, '-m', 'sherlock', '--no-color', username]
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=120,
            cwd=os.path.expanduser('~')
        )

        if result.returncode != 0:
            error_message = result.stderr or result.stdout
            return [{'type': 'Error', 'value': f"Sherlock exited with an error: {error_message}", 'source': 'Sherlock'}]

        # Count the number of found profiles for the summary
        found_lines = [line for line in result.stdout.splitlines() if line.startswith('[+]')]
        profile_count = len(found_lines)

        summary_value = f"Found {profile_count} profiles for username '{username}'"
        
        findings = [{
            'type': 'Sherlock Scan', 
            'value': summary_value, 
            'source': 'Sherlock',
            'details': result.stdout # Store the raw, formatted stdout
        }]

        return findings
    except FileNotFoundError:
        return [{'type': 'Error', 'value': 'Sherlock not found. Make sure it is installed and in your PATH.', 'source': 'System'}]
    except subprocess.TimeoutExpired:
        return [{'type': 'Error', 'value': 'Sherlock scan timed out after 2 minutes.', 'source': 'Sherlock'}]
    except Exception as e:
        return [{'type': 'Error', 'value': f"An unexpected error occurred: {e}", 'source': 'Sherlock'}]
