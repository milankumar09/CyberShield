from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
import tldextract
import re
import email
from email.header import decode_header
import ssl
import socket
import requests
import json
from datetime import datetime

# Try to import whois, but make it optional
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: whois module not available. Domain age checking will be disabled.")

app = Flask(__name__)

def analyze_email_headers(email_content):
    try:
        msg = email.message_from_string(email_content)
        headers = []
        
        # Check for common phishing indicators in headers
        for header in ['From', 'To', 'Subject', 'Date', 'Return-Path', 'Received']:
            if header in msg:
                value = msg[header]
                if isinstance(value, str):
                    value = decode_header(value)[0][0]
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='ignore')
                
                status = 'safe'
                reason = ''
                
                # Check for suspicious patterns
                if header == 'From':
                    if '@' not in value:
                        status = 'suspicious'
                        reason = 'Invalid email format'
                    elif 'noreply' in value.lower():
                        status = 'suspicious'
                        reason = 'No-reply address'
                
                headers.append({
                    'name': header,
                    'value': value,
                    'status': status,
                    'reason': reason
                })
        
        return headers
    except Exception as e:
        print(f"Error analyzing headers: {str(e)}")
        return []

def analyze_links(email_content):
    try:
        soup = BeautifulSoup(email_content, 'html.parser')
        links = []
        
        for a in soup.find_all('a', href=True):
            url = a['href']
            status = 'safe'
            reason = ''
            
            # Check for suspicious patterns
            if not url.startswith(('http://', 'https://')):
                status = 'suspicious'
                reason = 'Non-HTTP/HTTPS link'
            elif 'bit.ly' in url or 'tinyurl.com' in url:
                status = 'suspicious'
                reason = 'URL shortener detected'
            elif '@' in url:
                status = 'suspicious'
                reason = 'Email address in URL'
            
            links.append({
                'url': url,
                'status': status,
                'reason': reason
            })
        
        return links
    except Exception as e:
        print(f"Error analyzing links: {str(e)}")
        return []

def analyze_domain(domain):
    try:
        if not WHOIS_AVAILABLE:
            return {
                'age': 'Unknown (whois module not available)',
                'ssl_status': check_ssl(domain),
                'blacklist_status': check_blacklist(domain)
            }
            
        domain_info = whois.whois(domain)
        current_date = datetime.now()
        
        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            
            age_days = (current_date - creation_date).days
            age_years = age_days // 365
            
            return {
                'age': f"{age_years} years",
                'ssl_status': check_ssl(domain),
                'blacklist_status': check_blacklist(domain)
            }
    except Exception as e:
        print(f"Error analyzing domain: {str(e)}")
        return {
            'age': 'Unknown',
            'ssl_status': 'Unknown',
            'blacklist_status': 'Unknown'
        }

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return 'Valid'
    except Exception as e:
        print(f"Error checking SSL: {str(e)}")
        return 'Invalid'

def check_blacklist(domain):
    try:
        # Check against Google Safe Browsing API (you'll need to add your API key)
        response = requests.get(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY")
        if response.status_code == 200:
            return 'Clean'
        return 'Unknown'
    except Exception as e:
        print(f"Error checking blacklist: {str(e)}")
        return 'Unknown'

def analyze_attachments(email_content):
    try:
        msg = email.message_from_string(email_content)
        attachments = []
        
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if filename:
                status = 'safe'
                reason = ''
                
                # Check for suspicious file types
                if filename.lower().endswith(('.exe', '.bat', '.cmd', '.msi', '.dll')):
                    status = 'phishing'
                    reason = 'Executable file detected'
                elif filename.lower().endswith(('.zip', '.rar', '.7z')):
                    status = 'suspicious'
                    reason = 'Archive file detected'
                
                attachments.append({
                    'name': filename,
                    'type': 'document',
                    'status': status,
                    'reason': reason
                })
        
        return attachments
    except Exception as e:
        print(f"Error analyzing attachments: {str(e)}")
        return []

def analyze_language_patterns(email_content):
    try:
        risk_factors = []
        
        # Check for urgency
        urgency_phrases = ['urgent', 'immediately', 'asap', 'right away', 'hurry']
        if any(phrase in email_content.lower() for phrase in urgency_phrases):
            risk_factors.append({
                'title': 'Urgency Detected',
                'description': 'Email contains urgent language which is common in phishing attempts',
                'severity': 'medium'
            })
        
        # Check for threats
        threat_phrases = ['account suspended', 'security alert', 'verify your account', 'password expired']
        if any(phrase in email_content.lower() for phrase in threat_phrases):
            risk_factors.append({
                'title': 'Threatening Language',
                'description': 'Email contains threatening language to create urgency',
                'severity': 'high'
            })
        
        # Check for poor grammar
        if len(re.findall(r'\b[a-z]{2,}\b', email_content.lower())) > 100:
            risk_factors.append({
                'title': 'Poor Grammar',
                'description': 'Email contains multiple grammatical errors',
                'severity': 'low'
            })
        
        return risk_factors
    except Exception as e:
        print(f"Error analyzing language patterns: {str(e)}")
        return []

def generate_recommendations(analysis_results):
    try:
        recommendations = []
        
        if any(link['status'] == 'suspicious' for link in analysis_results['links']):
            recommendations.append({
                'title': 'Suspicious Links',
                'description': 'Do not click on any links in this email. Verify the sender and content before taking any action.'
            })
        
        if any(attachment['status'] == 'phishing' for attachment in analysis_results['attachments']):
            recommendations.append({
                'title': 'Dangerous Attachments',
                'description': 'Do not open any attachments. They may contain malware or viruses.'
            })
        
        if any(header['status'] == 'suspicious' for header in analysis_results['headers']):
            recommendations.append({
                'title': 'Suspicious Headers',
                'description': 'The email headers show signs of potential spoofing. Verify the sender through other means.'
            })
        
        if analysis_results['domain_info']['age'] == 'Unknown':
            recommendations.append({
                'title': 'Unknown Domain',
                'description': 'The sender\'s domain could not be verified. Exercise caution.'
            })
        
        return recommendations
    except Exception as e:
        print(f"Error generating recommendations: {str(e)}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'email' in request.files:
            email_file = request.files['email']
            email_content = email_file.read().decode('utf-8', errors='ignore')
        else:
            email_content = request.form.get('content', '')
        
        # Extract domain from email content
        domain = None
        for line in email_content.split('\n'):
            if 'From:' in line:
                email_match = re.search(r'[\w\.-]+@[\w\.-]+', line)
                if email_match:
                    domain = tldextract.extract(email_match.group()).domain
        
        # Perform analysis
        headers = analyze_email_headers(email_content)
        links = analyze_links(email_content)
        domain_info = analyze_domain(domain) if domain else {
            'age': 'Unknown',
            'ssl_status': 'Unknown',
            'blacklist_status': 'Unknown'
        }
        attachments = analyze_attachments(email_content)
        risk_factors = analyze_language_patterns(email_content)
        
        # Calculate overall score and verdict
        score = 0.0
        if links:
            score += sum(1 for link in links if link['status'] == 'safe') / len(links) * 0.3
        if headers:
            score += sum(1 for header in headers if header['status'] == 'safe') / len(headers) * 0.3
        if attachments:
            score += sum(1 for attachment in attachments if attachment['status'] == 'safe') / len(attachments) * 0.2
        if risk_factors:
            score += sum(0.5 for factor in risk_factors if factor['severity'] == 'low') / len(risk_factors) * 0.2
        
        # Determine verdict and threat level
        if score >= 0.8:
            verdict = 'Safe'
            threat_level = 'low'
        elif score >= 0.5:
            verdict = 'Suspicious'
            threat_level = 'medium'
        else:
            verdict = 'Phishing'
            threat_level = 'high'
        
        # Generate recommendations
        recommendations = generate_recommendations({
            'links': links,
            'headers': headers,
            'attachments': attachments,
            'domain_info': domain_info
        })
        
        # Prepare response
        response = {
            'verdict': verdict,
            'threatLevel': threat_level,
            'threatScore': 1 - score,
            'score': score,
            'domainAge': domain_info['age'],
            'sslStatus': domain_info['ssl_status'],
            'blacklistStatus': domain_info['blacklist_status'],
            'emailPreview': email_content[:500] + '...' if len(email_content) > 500 else email_content,
            'links': links,
            'headers': headers,
            'attachments': attachments,
            'riskFactors': risk_factors,
            'recommendations': recommendations
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in analyze endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 