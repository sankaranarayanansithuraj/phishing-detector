RESPONSES = {
    'HIGH': {
        'actions': [
            '🚨 Immediately block sender and quarantine the message',
            '🔒 Force password reset on all targeted accounts',
            '📢 Escalate to SOC team and Tier 2 incident response',
            '🕵️ Preserve all email headers and metadata for forensic analysis',
            '🌐 Block all extracted URLs at the firewall/proxy level',
            '📋 File a formal incident report in the ticketing system',
            '🔍 Scan if other users received the same message',
            '📵 Disable any compromised accounts until investigation is complete',
        ],
        'urgency': 'Immediate — respond within 15 minutes',
        'color': '🔴',
        'description': 'Critical threat detected. This message shows strong indicators of a targeted phishing attack.'
    },
    'MEDIUM': {
        'actions': [
            '⚠️ Move message to spam or quarantine folder',
            '🔔 Notify the recipient about the potential threat',
            '🌐 Analyze and selectively block suspicious URLs',
            '📊 Log the incident in the threat intelligence database',
            '👀 Monitor the targeted account for unusual activity for 24–48 hours',
            '📧 Send a phishing awareness reminder to the affected user',
        ],
        'urgency': 'High — respond within 1–4 hours',
        'color': '🟡',
        'description': 'Moderate threat detected. Message contains several suspicious indicators that require investigation.'
    },
    'LOW': {
        'actions': [
            'ℹ️ Flag message as suspicious for user awareness',
            '📝 Log the message for pattern analysis and future reference',
            '📧 Send a security awareness notification to the recipient',
            '👁️ Monitor for repeated patterns from the same sender',
        ],
        'urgency': 'Normal — respond within 24 hours',
        'color': '🟢',
        'description': 'Low-level threat. Message shows minor suspicious patterns but no immediate danger.'
    }
}

def get_response_plan(severity):
    return RESPONSES.get(severity, RESPONSES['LOW'])