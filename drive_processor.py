import json
from datetime import datetime
from alert_utils import send_email_alert
from db_helpers import insert_phishing_alert


def process_drive_event(item, CONFIG):
    """
    Analyze Google Drive audit logs for potential phishing or impersonation attempts.
    """
    DOMAIN = CONFIG['domain']
    params = {p['name']: p.get('value', '') for p in item.get('parameters', [])}
    actor = item.get('actor', {}).get('email', 'unknown')
    timestamp = datetime.strptime(item['id']['time'], '%Y-%m-%dT%H:%M:%S.%fZ')
    event_name = item.get('name', '')

    visibility = params.get('new_value', '')
    visibility_change = params.get('visibility_change', '')
    owner_domain = params.get('primary_owner') or params.get('owner_domain', '')
    owner_display_name = params.get('owner_display_name', '')
    doc_id = params.get('doc_id', '')
    title = params.get('doc_title', 'Untitled Document')
    file_link = f"https://drive.google.com/open?id={doc_id}" if doc_id else "N/A"

    is_phishing_risk = False
    reasons = []

    # Rule 1: Document shared with "anyone with the link" (especially from external)
    # Check various forms of public sharing
    public_sharing_indicators = CONFIG.get('phishing', {}).get('public_sharing_indicators', [
        'anyoneWithLink', 'anyone_with_link', 'anyone', 'public', 
        'anyoneWithTheLink', 'anyone_with_the_link'
    ])
    is_public_share = any(indicator.lower() in str(visibility).lower() for indicator in public_sharing_indicators)
    is_external_owner = DOMAIN not in str(owner_domain).lower() if owner_domain else True
    
    if is_public_share:
        if is_external_owner:
            is_phishing_risk = True
            reasons.append(f"External user shared document with 'anyone with the link' visibility: {visibility}")
        else:
            # Even internal users sharing publicly could be suspicious
            reasons.append(f"Document shared with 'anyone with the link' visibility: {visibility}")

    # Rule 2: Impersonation attempt - especially superintendent or principal
    display_lower = owner_display_name.lower() if owner_display_name else ''
    # Check for impersonation keywords, especially superintendent and principal
    impersonation_keywords = CONFIG.get('phishing', {}).get('impersonation_keywords', [
        'superintendent', 'principal', 'superintendant', 'prinicipal'
    ])
    leadership_keywords = CONFIG.get('phishing', {}).get('leadership_keywords', [
        'finance', 'hr', 'human resources', 'chief', 'director', 'executive'
    ])
    
    is_impersonation = False
    if display_lower:
        # High priority: superintendent or principal
        if any(k in display_lower for k in impersonation_keywords):
            is_impersonation = True
            if is_external_owner:
                is_phishing_risk = True
                reasons.append(f"HIGH PRIORITY: External user impersonating leadership role: {owner_display_name}")
            else:
                # Even internal, flag if combined with public sharing
                if is_public_share:
                    is_phishing_risk = True
                    reasons.append(f"Potential impersonation attempt (internal user): {owner_display_name}")
        # Medium priority: other leadership roles
        elif any(k in display_lower for k in leadership_keywords):
            if is_external_owner and is_public_share:
                is_phishing_risk = True
                reasons.append(f"External user with leadership-sounding name: {owner_display_name}")

    # Rule 3: Suspicious file extension
    title_lower = title.lower() if title else ''
    suspicious_extensions = CONFIG.get('phishing', {}).get('suspicious_extensions', [
        '.exe', '.scr', '.bat', '.zip', '.js', '.vbs', '.cmd'
    ])
    if any(ext in title_lower for ext in suspicious_extensions):
        if is_external_owner or is_public_share:
            is_phishing_risk = True
            reasons.append(f"Suspicious file extension: {title}")

    # Rule 4: Combined risk factors - public share + impersonation
    if is_public_share and is_impersonation and is_external_owner:
        is_phishing_risk = True
        reasons.append("CRITICAL: Public sharing combined with impersonation attempt")

    if is_phishing_risk:
        reason_text = '; '.join(reasons)
        subject = f"{CONFIG['alerts']['alert_subject_prefix']} PHISHING ALERT: Suspicious Drive Share to {actor}"
        msg = (
            f"A potential phishing or impersonation share was detected.\n\n"
            f"Reason: {reason_text}\n\n"
            f"User: {actor}\n"
            f"File: {title}\n"
            f"Owner Domain: {owner_domain}\n"
            f"Owner Display Name: {owner_display_name}\n"
            f"Link: {file_link}\n"
            f"Visibility: {visibility}\n"
            f"Time: {timestamp}\n"
            f"Event Type: {event_name}\n"
        )

        send_email_alert(subject, msg)
        insert_phishing_alert(
            actor,
            owner_domain,
            owner_display_name,
            doc_id,
            title,
            file_link,
            visibility,
            visibility_change,
            reason_text,
            item,
            True
        )
