import re
from urllib.parse import urlparse

def extract_features(url):

    features = []
    details = {}

    parsed = urlparse(url)

    # 1 Number of dots
    features.append(url.count("."))
    
    # 2 Subdomain level
    features.append(len(parsed.netloc.split(".")) - 1)

    # 3 Path level
    features.append(len(parsed.path.split("/")))

    # 4 URL length
    features.append(len(url))

    # 5 Number of dash
    features.append(url.count("-"))

    # 6 Number of digits
    features.append(sum(c.isdigit() for c in url))

    # 7 IP address in URL
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        features.append(1)
        details['IP Address in URL'] = True
    else:
        features.append(0)

    # 8 Hostname length
    features.append(len(parsed.netloc))

    # 9 Path length
    features.append(len(parsed.path))

    # 10 Query length
    features.append(len(parsed.query))

    # 11 HTTPS used
    if url.startswith("https"):
        features.append(0)
        details['Uses strict HTTPS'] = True
    else:
        features.append(1)
        details['No strict HTTPS'] = True

    # 12 Suspicious words
    suspicious_words = ["login","verify","update","secure","account","bank","confirm","password"]
    count = 0
    found_words = []
    for word in suspicious_words:
        if word in url.lower():
            count += 1
            found_words.append(word)

    features.append(count)
    if count > 0:
        details['Suspicious Words Found'] = ", ".join(found_words)

    # 13 Suspicious TLD
    suspicious_tld = [".xyz",".tk",".ml",".ga",".cf"]
    flag = 0
    for tld in suspicious_tld:
        if url.endswith(tld):
            flag = 1
            details['Suspicious TLD Used'] = tld

    features.append(flag)

    # 14 Number of subdirectories
    features.append(parsed.path.count("/"))

    # 15 '@' symbol
    if "@" in url:
        features.append(1)
        details['Contains @ Symbol'] = True
    else:
        features.append(0)

    # 16 double slash redirect
    if "//" in parsed.path:
        features.append(1)
        details['Contains Double Slash Redirect'] = True
    else:
        features.append(0)

    # 17 '=' symbol
    features.append(url.count("="))

    # 18 '&' symbol
    features.append(url.count("&"))

    # 19 '?' symbol
    features.append(url.count("?"))

    # 20 '%' symbol
    features.append(url.count("%"))

    # Fill remaining features up to 48
    while len(features) < 48:
        features.append(0)

    return features, details