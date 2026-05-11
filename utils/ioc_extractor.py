import re

PHISHING_KEYWORDS = [
    'verify', 'account suspended', 'click here', 'urgent', 'immediately',
    'password', 'login', 'confirm', 'update your', 'limited time',
    'you have won', 'free gift', 'bank account', 'credit card',
    'social security', 'immediate action', 'expire', 'suspicious activity',
    'unusual sign', 'reset your', 'validate', 'billing information',
    'act now', 'risk', 'compromised', 'unauthorized', 'security alert',
    'dear customer', 'dear user', 'kindly', 'reactivate'
]

def extract_urls(text):
    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(pattern, text, re.IGNORECASE)

def extract_emails(text):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    return re.findall(pattern, text)

def extract_ip_addresses(text):
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(pattern, text)

def extract_suspicious_keywords(text):
    found = []
    text_lower = text.lower()
    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            found.append(keyword)
    return found

def check_url_features(urls):
    suspicious = []
    for url in urls:
        flags = []
        if len(url) > 75:
            flags.append("very long URL")
        if url.count('.') > 4:
            flags.append("too many subdomains")
        if '@' in url:
            flags.append("@ symbol in URL")
        if any(x in url.lower() for x in ['-login', 'secure-', 'verify', 'update', 'account', 'signin']):
            flags.append("suspicious URL keyword")
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            flags.append("IP address used instead of domain")
        if url.count('-') > 3:
            flags.append("excessive hyphens")
        if flags:
            suspicious.append({'url': url, 'flags': flags})
    return suspicious

def extract_iocs(text):
    urls             = extract_urls(text)
    emails           = extract_emails(text)
    ips              = extract_ip_addresses(text)
    keywords         = extract_suspicious_keywords(text)
    suspicious_urls  = check_url_features(urls)

    return {
        'urls': urls,
        'emails': emails,
        'ip_addresses': ips,
        'suspicious_keywords': keywords,
        'suspicious_urls': suspicious_urls,
        'ioc_count': len(urls) + len(keywords) + len(suspicious_urls) + len(ips)
    }