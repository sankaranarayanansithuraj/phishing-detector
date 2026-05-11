def calculate_severity(prediction_proba, iocs):
    """
    prediction_proba : float 0.0–1.0  (model confidence it is phishing)
    iocs             : dict from extract_iocs()
    Returns          : (severity_label, risk_score)
    """
    score = 0

    # ML confidence (max 50 points)
    if prediction_proba >= 0.85:
        score += 50
    elif prediction_proba >= 0.70:
        score += 38
    elif prediction_proba >= 0.55:
        score += 25
    elif prediction_proba >= 0.40:
        score += 12

    # Suspicious keywords (max 20 points)
    score += min(len(iocs['suspicious_keywords']) * 4, 20)

    # Suspicious URLs (max 20 points)
    score += min(len(iocs['suspicious_urls']) * 8, 20)

    # Raw URLs (max 6 points)
    score += min(len(iocs['urls']) * 2, 6)

    # IP addresses found (max 4 points)
    score += min(len(iocs['ip_addresses']) * 4, 4)

    # Classify
    if score >= 60:
        return 'HIGH', score
    elif score >= 30:
        return 'MEDIUM', score
    else:
        return 'LOW', score