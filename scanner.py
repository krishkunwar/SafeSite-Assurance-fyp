import requests
import random
from urllib.parse import urlparse
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509.oid import SignatureAlgorithmOID
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from datetime import datetime
import requests.exceptions
from random import choice


def parse_rfc4514_string(rfc4514_string):
    components = []
    current_component = []
    escape_next_char = False
    for char in rfc4514_string:
        if escape_next_char:
            current_component.append(char)
            escape_next_char = False
        elif char == '\\':
            escape_next_char = True
        elif char == ',':
            components.append(''.join(current_component))
            current_component = []
        else:
            current_component.append(char)
    components.append(''.join(current_component)) 
    
    parsed = {}
    for component in components:
        key, _, value = component.partition('=')
    
        parsed[key.strip()] = value.strip()
    return parsed


def get_security_headers(url):
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Opera/58.0.3135.107 Safari/537.36',
    ]

    headers = {'User-Agent': random.choice(user_agents)}

    try:
        response = requests.get(url, headers=headers)
        final_headers = response.headers

        # Define important security headers and their descriptions
        important_headers = {
            "Content-Security-Policy": "Defines which sources the browser should allow to load resources from, helping prevent XSS attacks by restricting where content can be loaded from.",
            "Strict-Transport-Security": "Tells the browser to only access the website using HTTPS, reducing the risk of Man-in-the-Middle attacks.",
            "X-Content-Type-Options": "Prevents the browser from performing MIME type sniffing, and forces it to stick with the declared content-type.",
            "X-Frame-Options": "Protects users against clickjacking attacks by preventing the webpage from being framed by other sites.",
            "Referrer-Policy": "Controls how much referrer information (the page a user came from) should be included with requests.",
            "Permissions-Policy": "Allows a site to enable or disable certain web features and APIs in the browser, such as the camera or microphone.",
            "Feature-Policy": "Deprecated. Similar to Permissions-Policy, it was used to control which features and APIs could be used in the browser.",
            "X-XSS-Protection": "Configures the XSS protection mechanism of the browser, instructing it to block the page from loading when a potential XSS attack is detected."
        }


        present_headers = {}
        absent_headers = {}

        for header, description in important_headers.items():
            if header in final_headers:
                present_headers[header] = {"description": description}
            else:
                absent_headers[header] = {"description": description}

        return present_headers, absent_headers, dict(final_headers)

    except requests.RequestException as e:
        return f"Error fetching headers: {e}", {}, {}
    

def get_ip_address(url):
    try:
        domain_name = url.split('//')[-1].split('/')[0]  # Extract domain from URL
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return "IP not found"
    
def check_hostname(cert, domain_name):
    """ Check if the certificate is valid for the given domain name. """
    try:
        # Get the SANs from the certificate
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        valid_domains = san.value.get_values_for_type(x509.DNSName)
        return domain_name in valid_domains
    except x509.ExtensionNotFound:
        # Fallback to CN if no SAN is present
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return domain_name == cn
    
def get_ssl_info(domain_name):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain_name, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                cert_bin = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                public_key = cert.public_key()

                # Parsing issuer and subject using a hypothetical parsing function
                issuer_info = parse_rfc4514_string(cert.issuer.rfc4514_string())
                subject_info = parse_rfc4514_string(cert.subject.rfc4514_string())
                valid = cert.not_valid_after > datetime.now() and cert.not_valid_before < datetime.now()
                
               
                valid &= check_hostname(cert, domain_name)
                

              
                key_usage_info = "Not Available"
                try:
                    key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                    key_usage_info = ', '.join(
                        name for name, value in [
                            ('Digital Signature', key_usage_ext.digital_signature),
                            ('Non Repudiation', key_usage_ext.content_commitment),
                            ('Key Encipherment', key_usage_ext.key_encipherment),
                            ('Data Encipherment', key_usage_ext.data_encipherment),
                            ('Key Agreement', key_usage_ext.key_agreement),
                            ('Certificate Signing', key_usage_ext.key_cert_sign),
                            ('CRL Signing', key_usage_ext.crl_sign),
                            ('Encipher Only', key_usage_ext.encipher_only if key_usage_ext.key_agreement else False),
                            ('Decipher Only', key_usage_ext.decipher_only if key_usage_ext.key_agreement else False)
                        ] if value
                    )
                except x509.ExtensionNotFound:
                    pass

              
                extended_key_usage_info = "Not Available"
                try:
                    extended_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                    extended_key_usage_info = ', '.join(usage._name for usage in extended_key_usage)
                except x509.ExtensionNotFound:
                    pass

              
                public_key_algorithm = {
                    rsa.RSAPublicKey: 'RSA',
                    dsa.DSAPublicKey: 'DSA',
                    ec.EllipticCurvePublicKey: 'Elliptic Curve'
                }.get(type(public_key), 'Unknown')

          
                if public_key_algorithm == 'Unknown':
                    if isinstance(public_key, rsa.RSAPublicKey):
                        public_key_algorithm = 'RSA'
                    elif isinstance(public_key, dsa.DSAPublicKey):
                        public_key_algorithm = 'DSA'
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        public_key_algorithm = 'Elliptic Curve'
                    else:
                        public_key_algorithm = 'Other/Unsupported'
                        
                days_until_expire = (cert.not_valid_after - datetime.now()).days

                ssl_details = {
                    'Issuer': issuer_info,  
                    'Subject': subject_info,
                    'Valid From': cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
                    'Valid To': cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
                    'Days Left to Expire': days_until_expire,
                    'Certificate Version': cert.version.name,
                    'Serial Number': format(cert.serial_number, 'X'),
                    'Signature Algorithm': cert.signature_algorithm_oid._name,
                    'Public Key': public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8'),
                    'Public Key Algorithm': public_key_algorithm,
                    'Key Usage': key_usage_info,
                    'Extended Key Usage': extended_key_usage_info,
                     'Valid': valid
                }
                return ssl_details

    except (ssl.SSLError, socket.timeout, ConnectionResetError) as e:
        return {
            'error': f"SSL certificate could not be fetched: {e}",
            'Issuer':  {'Issuer': 'Unavailable'},
            'Subject': {'Subject': 'Unavailable'},
            'Valid From': 'Not available',
            'Valid To': 'Not available',
            'Days Left to Expire': 'Not applicable',
            'Certificate Version': 'Not available',
            'Serial Number': 'Not available',
            'Signature Algorithm': 'Not available',
            'Public Key': 'Not available',
            'Public Key Algorithm': 'Not available',
            'Key Usage': 'Not available',
            'Extended Key Usage': 'Not available',
            'Valid': False
        }


def fetch_and_parse_robots(url):
    try:
        response = requests.get(f"{url}/robots.txt", timeout=20)
        response.raise_for_status()
        lines = response.text.splitlines()

        annotated_text = "<div class='robots-content'>"
        for line in lines:
            line = line.strip()
            if not line:  
                annotated_text += "<br>"
                continue
            
            if line.startswith('#'):
                annotated_text += f"<div>{line}</div>"  
                continue

            if 'User-agent:' in line:
                user_agent = line.split(':', 1)[1].strip() if ':' in line else ''
                if '*' in user_agent:
                    annotated_text += f"<div data-tooltip='This rule applies to all web crawlers.'>{line}</div>"
                else:
                    annotated_text += f"<div data-tooltip='The specific web crawler to which you are giving crawl instructions (usually a search engine).'>{line}</div>"
            elif 'Allow:' in line:
                path = line.split(':', 1)[1].strip() if ':' in line else ''
                if path == '/':
                    annotated_text += f"<div data-tooltip='The specified user-agent is allowed to access all parts of the website from the root directory onwards.'>{line}</div>"
                else:
                    annotated_text += f"<div data-tooltip='Paths that the specified user-agent is allowed to access.'>{line}</div>"
            elif 'Disallow:' in line:
                path = line.split(':', 1)[1].strip() if ':' in line else ''
                if path == '/':
                    annotated_text += f"<div data-tooltip='This disallows the specified user-agent from accessing the root directory and all subdirectories.'>{line}</div>"
                else:
                    annotated_text += f"<div data-tooltip='These paths are not allowed to be crawled by the user-agent.'>{line}</div>"
            else:
                annotated_text += f"<div>{line}</div>"  

        annotated_text += "</div>"
        return True, annotated_text
    except requests.RequestException as e:
        print(f"Failed to fetch robots.txt: {e}")
        return False

def fetch_security_txt(domain):
    urls = [f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt"]
    for url in urls:
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()  
            lines = response.text.splitlines()

            annotated_text = "<div class='security-content'>"
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                key, sep, value = line.partition(':')
                if key and value:
                    tooltip = "Information not specified"
                    if "Contact" in key:
                        tooltip = "Contact information for security concerns."
                    elif "Expires" in key:
                        tooltip = "The expiration date for this security policy."
                    elif "Encryption" in key:
                        tooltip = "Encryption keys or methods recommended for secure communication."
                    elif "Acknowledgments" in key:
                        tooltip = "Link to page where security contributors are acknowledged."
                    elif "Preferred-Languages" in key:
                        tooltip = "Preferred languages for security communications."
                    elif "Canonical" in key:
                        tooltip = "The canonical URL for this security policy."
                    elif "Policy" in key:
                        tooltip = "Link to the detailed security policy."
                    elif "Hiring" in key:
                        tooltip = "Information about recruitment for security-related roles."

                    annotated_text += f"<div data-tooltip='{tooltip}'>{line}</div>"
                else:
                    annotated_text += f"<div>{line}</div>"
            annotated_text += "</div>"
            return True, annotated_text

        except requests.RequestException as e:
            print(f"Failed to fetch {url}: {e}")
    return False

def validate_url(input_url):
    # List of browser-like user-agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',  # Chrome
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',  # Edge
        'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',  # Internet Explorer
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 OPR/47.0.2631.71'  # Opera
    ]

    # Choose a random user-agent
    headers = {
        'User-Agent': choice(user_agents)
    }
    if not input_url.startswith(('http://', 'https://')):
        input_url = 'https://' + input_url 

    try:
        result = urlparse(input_url)
        if all([result.scheme, result.netloc]):
            final_url = input_url.replace('http://', 'https://') if result.scheme == 'http' else input_url
            try:
               
                response = requests.head(final_url, timeout=5, headers=headers)
                response.raise_for_status()
            except requests.RequestException:
              
                try:
                    response = requests.get(final_url, timeout=5, stream=True, headers=headers)
                    response.raise_for_status()
                    response.close()  
                except requests.RequestException:
                   
                    if final_url.startswith('https://'):
                        final_url = final_url.replace('https://', 'http://')
                        try:
                            response = requests.head(final_url, timeout=5, headers=headers)
                            response.raise_for_status()
                        except requests.RequestException:
                            print(f"HTTP request failed for URL {final_url}")
                            return '404.html'  
                    else:
                        return '404.html'
            return final_url  
        else:
            print("URL does not have a valid format.")
            return '404.html'
    except socket.gaierror as e:
        print(f"DNS resolution failed for URL {input_url}: {e}")
        return '404.html'
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        return '404.html'
    
def calculate_security_grade(present_headers, ssl_info, robots_exists, security_exists):
    score = 0
    max_score = 100  

    # Points assigned to each criterion
    points_per_header = 6.25
    ssl_points = 30
    robots_points = 10
    security_txt_points = 10

    important_headers = [
        "Content-Security-Policy", "Strict-Transport-Security",
        "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
        "Permissions-Policy", "X-XSS-Protection", "Feature-Policy"
    ]

    for header in important_headers:
        if header in present_headers:
            score += points_per_header

    if ssl_info.get('Valid', False):
        score += ssl_points

    if robots_exists:
        score += robots_points  

    if security_exists:
        score += security_txt_points  

    # Ensure the score doesn't exceed the maximum score
    score = min(score, max_score)

    # Calculate grade percentage
    grade_percentage = (score / max_score) * 100

    return grade_percentage









