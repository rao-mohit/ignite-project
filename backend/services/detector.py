import re
from typing import List, Dict, Any

URGENCY_PATTERNS = [
    r"\b(urgent|immediately|action required|account suspended|account blocked|suspended within \d+ hours|final warning|last notice|deactivated|expire[s]? today|immediate action|unauthorized access|security breach)\b",
    r"\b(within \d+ (minutes|hours|days)|lock your account|terminated|penalty|legal action|police|lawsuit|disconnected|power cut|unpaid bill)\b"
]

CREDENTIAL_HARVESTING_PATTERNS = [
    r"\b(verify your (account|password|identity|ssn|pin|otp|credentials)|click here to login|update your payment|confirm your details|re-enter password)\b",
    r"\b(one-time password|otp is|do not share|enter pin|bank account details|credit card number|cvv|security code|enter otp|verify otp|share otp|pan details|update kyc|kyc update|netbanking)\b"
]

FINANCIAL_SCAM_PATTERNS = [
    r"\b(won a prize|congratulations|lottery winner|claim your reward|\$\d+,\d+|\$\d+ free|bitcoin|crypto investment|guaranteed return|wire transfer|gift card|cash prize|claim \$|rs \d+|cash prize of)\b",
    r"\b(refund of \$\d+|unpaid invoice|tax refund|overdue payment|loan approved|instant credit|reward points)\b"
]

IMPERSONATION_PATTERNS = [
    r"\b(customer support|helpdesk|security team|bank officer|tax authority|irs|fedex|ups|dhl|amazon support|apple id|netflix billing|geek squad|sbi|hdfc|icici|kbc|electricity officer|whatsapp support)\b"
]

WHATSAPP_SCAM_PATTERNS = [
    r"\b(part-time job|part time job|wfh job|work from home|earn \d+ daily|earn rs \d+|like (youtube|yt) videos|telegram task|joining bonus|rating task|prepaid task|daily payment)\b",
    r"\b(whatsapp (security|code|pin)|verify your 6-digit|6-digit code|dropped my phone|temporary number|new number send money|hi mum|hi dad)\b"
]

def analyze_scam_rules(text: str) -> Dict[str, Any]:
    text_lower = text.lower()
    reasons: List[str] = []
    points = 0
    categories = []

    # 1. Check Urgency
    urgency_matches = 0
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            urgency_matches += 1
    if urgency_matches > 0:
        points += 25 * urgency_matches
        reasons.append("High urgency language designed to cause panic or swift action")
        categories.append("Urgency & Coercion")

    # 2. Check Credential & OTP Harvesting
    harvest_matches = 0
    for pattern in CREDENTIAL_HARVESTING_PATTERNS:
        if re.search(pattern, text_lower):
            harvest_matches += 1
    if harvest_matches > 0:
        points += 35 * harvest_matches
        reasons.append("Requests for sensitive credentials, OTPs, PINs, or password verification")
        categories.append("Credential Harvesting")

    # 3. Check Financial / Prize Scams
    financial_matches = 0
    for pattern in FINANCIAL_SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            financial_matches += 1
    if financial_matches > 0:
        points += 30 * financial_matches
        reasons.append("Financial incentive, lottery/prize claim, or refund lure detected")
        categories.append("Financial & Lottery Scam")

    # 4. Check Impersonation
    impersonation_matches = 0
    for pattern in IMPERSONATION_PATTERNS:
        if re.search(pattern, text_lower):
            impersonation_matches += 1
    if impersonation_matches > 0:
        points += 20 * impersonation_matches
        reasons.append("Impersonation of trusted institutions, banks, or support services")
        categories.append("Brand / Official Impersonation")

    # 5. Check WhatsApp Specific Lures (Job/Telegram/Account Theft)
    wa_matches = 0
    for pattern in WHATSAPP_SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            wa_matches += 1
    if wa_matches > 0:
        points += 50 * wa_matches
        reasons.append("WhatsApp/Telegram scam vector detected (Fake Part-Time Job / Account Hijack / PIN Theft)")
        categories.append("WhatsApp & Social Engineering")

    rule_score = min(100, points)

    return {
        "rule_score": rule_score,
        "reasons": reasons,
        "categories": list(set(categories))
    }
