import requests
import json
import re
import logging
from email import message_from_string
from email.header import decode_header
from urllib.parse import urlparse, urlunparse
from imaplib import IMAP4_SSL
from base64 import b64decode
from time import sleep
from email.utils import parseaddr

# Configure logging
logging.basicConfig(filename='incident_response.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Required API keys
THREAT_INTEL_API_KEY = '[INSERT THREAT INTEL API KEY HERE]'
CROWDSTRIKE_API_KEY = '[INSERT CROWDSTRIKE API KEY HERE]'
AUTH_SERVICE_API_KEY = '[INSERT AUTH SERVICE API KEY HERE]'
REPORTING_API_KEY = '[INSERT REPORTING API KEY HERE]'

# User input for company details
ORG_DOMAIN = input("Please enter your organization domain (e.g., company.com): ").strip()

# Regular expressions for URL and email validation
URL_REGEX = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

# Error handling and retry for API requests
def make_api_request(url, headers, retries=3):
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"API request failed: {e}")
            if attempt + 1 == retries:
                raise e
            logging.info(f"Retrying API request... Attempt {attempt + 1}/{retries}")
            sleep(2)  # Wait before retrying
    return None

# Threat Intelligence querying with error handling and retries
def check_threat_intel(ioc, ioc_type):
    try:
        if ioc_type == 'url':
            url = f'https://threatintel.api/{ioc}'
        elif ioc_type == 'file':
            url = f'https://threatintel.api/file/{ioc}'
        headers = {'Authorization': f'Bearer {THREAT_INTEL_API_KEY}'}
        response = make_api_request(url, headers)
        if response and response.status_code == 200:
            data = response.json()
            return data.get('malicious', False)
    except Exception as e:
        logging.error(f"Error checking threat intelligence: {e}")
    return False

# Query CrowdStrike EDR for malware detection
def query_edr(user_email):
    try:
        url = f'https://crowdstrike.api/endpoint/{user_email}'
        headers = {'Authorization': f'Bearer {CROWDSTRIKE_API_KEY}'}
        response = make_api_request(url, headers)
        if response and response.status_code == 200:
            return response.json().get('endpoints', [])
    except Exception as e:
        logging.error(f"Error querying EDR for user {user_email}: {e}")
    return []

# Isolate endpoint via CrowdStrike
def isolate_endpoint(endpoint_id):
    try:
        url = f'https://crowdstrike.api/isolate/{endpoint_id}'
        headers = {'Authorization': f'Bearer {CROWDSTRIKE_API_KEY}'}
        response = requests.post(url, headers=headers)
        if response.status_code == 200:
            logging.info(f"Endpoint {endpoint_id} isolated successfully.")
        else:
            logging.error(f"Failed to isolate endpoint {endpoint_id}. Status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error isolating endpoint {endpoint_id}: {e}")

# Check for suspicious login activity
def check_login_activity(user_email):
    try:
        url = f'https://auth.api/login_activity/{user_email}'
        headers = {'Authorization': f'Bearer {AUTH_SERVICE_API_KEY}'}
        response = make_api_request(url, headers)
        if response and response.status_code == 200:
            return response.json().get('login_history', [])
    except Exception as e:
        logging.error(f"Error checking login activity for {user_email}: {e}")
    return []

# Lock user account in authentication service
def lock_account(user_email):
    try:
        url = f'https://auth.api/lock/{user_email}'
        headers = {'Authorization': f'Bearer {AUTH_SERVICE_API_KEY}'}
        response = requests.post(url, headers=headers)
        if response.status_code == 200:
            logging.info(f"User {user_email}'s account locked successfully.")
        else:
            logging.error(f"Failed to lock account for {user_email}. Status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error locking account for {user_email}: {e}")

# Generate incident report and log actions
def generate_report(report_data):
    try:
        url = 'https://reporting.api/generate'
        headers = {'Authorization': f'Bearer {REPORTING_API_KEY}'}
        response = requests.post(url, json=report_data, headers=headers)
        if response.status_code == 200:
            logging.info("Incident report generated successfully.")
        else:
            logging.error(f"Failed to generate incident report. Status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error generating report: {e}")

# Extract URLs from email body, sanitizing input
def extract_urls_from_body(body):
    urls = re.findall(URL_REGEX, body)
    return [url for url in urls if sanitize_url(url)]

# Email content sanitization
def sanitize_url(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ['http', 'https']:
            return None
        sanitized_url = parsed_url._replace(query='', fragment='')  # Strip query parameters and fragments
        return urlunparse(sanitized_url)
    except Exception as e:
        logging.error(f"Error sanitizing URL {url}: {e}")
        return None

# Validate email address
def is_valid_email(email):
    return re.match(EMAIL_REGEX, email) is not None

# Load phishing email data from IMAP or local file
def load_phishing_emails(imap=False, imap_server='', imap_user='', imap_password='', folder='INBOX'):
    emails = []
    if imap:
        try:
            with IMAP4_SSL(imap_server) as imap_conn:
                imap_conn.login(imap_user, imap_password)
                imap_conn.select(folder)
                result, data = imap_conn.search(None, 'ALL')
                for num in data[0].split():
                    result, msg_data = imap_conn.fetch(num, '(RFC822)')
                    emails.append(msg_data[0][1].decode('utf-8'))
                logging.info(f"Loaded {len(emails)} phishing emails from IMAP.")
        except Exception as e:
            logging.error(f"Error loading emails from IMAP: {e}")
    else:
        # Placeholder logic for loading emails from local files or a DB
        emails = ["[Email data here]", "[Email data here]"]
        logging.info(f"Loaded {len(emails)} phishing emails from local source.")
    return emails

# Extract IOCs from email content
def extract_iocs_from_email(email_content):
    email_message = message_from_string(email_content)
    urls, headers, attachments = [], {}, []
    
    # Extract URLs and sanitize them
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                body = part.get_payload(decode=True).decode('utf-8')
                urls.extend(extract_urls_from_body(body))
    else:
        body = email_message.get_payload(decode=True).decode('utf-8')
        urls.extend(extract_urls_from_body(body))
    
    # Extract headers
    headers = {k: decode_header(v) for k, v in email_message.items()}
    
    # Extract attachments
    for part in email_message.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append(part.get_filename())
    
    return urls, headers, attachments

# Check IOCs against Threat Intelligence feeds
def check_iocs(urls, attachments):
    malicious_urls, malicious_files = [], []
    
    for url in urls:
        if check_threat_intel(url, 'url'):
            malicious_urls.append(url)
    
    for file in attachments:
        if check_threat_intel(file, 'file'):
            malicious_files.append(file)
    
    return malicious_urls, malicious_files

# Main logic: process phishing emails
def process_phishing_emails(emails):
    for email_content in emails:
        user_email = extract_user_email(email_content)  # Extract user email from email content
        if not is_valid_email(user_email):
            logging.error(f"Invalid email address detected: {user_email}")
            continue
        
        urls, headers, attachments = extract_iocs_from_email(email_content)
        malicious_urls, malicious_files = check_iocs(urls, attachments)
        compromised_credentials = check_user_activity(user_email)
        malicious_endpoints = check_malware_on_endpoints(user_email)
        
        # Remediate based on findings
        remediate(user_email, malicious_endpoints, compromised_credentials)
        
        # Generate incident report
        generate_incident_report(user_email, malicious_urls, malicious_files, compromised_credentials, malicious_endpoints)

# Full remediation process
def remediate(user_email, malicious_endpoints, compromised_credentials):
    if malicious_endpoints:
        for endpoint in malicious_endpoints:
            isolate_endpoint(endpoint['endpoint_id'])
    if compromised_credentials:
        lock_account(user_email)

# Generate and log the incident report
def generate_incident_report(user_email, malicious_urls, malicious_files, compromised_credentials, malicious_endpoints):
    report_data = {
        'user_email': user_email,
        'malicious_urls': malicious_urls,
        'malicious_files': malicious_files,
        'compromised_credentials': compromised_credentials,
        'malicious_endpoints': malicious_endpoints,
    }
    generate_report(report_data)

# Main script execution
if __name__ == "__main__":
    # Load emails (either from IMAP or local)
    phishing_emails = load_phishing_emails(imap=False)  # Set to True for IMAP
    process_phishing_emails(phishing_emails)
    logging.info("Incident response completed for all phishing emails.")
