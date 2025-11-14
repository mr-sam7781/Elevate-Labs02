#!/usr/bin/env python3
def header_discrepancy_checks(msg):
warnings = []
from_hdr = msg.get('From', '')
reply_to = msg.get('Reply-To', '')
received = msg.get_all('Received', [])
# Simple checks
if reply_to and reply_to not in from_hdr:
warnings.append(f"Reply-To differs from From: Reply-To={reply_to}")
if from_hdr and ('@' in from_hdr):
# check for suspicious looking display names (e.g., 'IT Support' but domain different)
pass
# Received headers presence
if not received:
warnings.append('No Received headers found (could be crafted).')
return warnings




def analyze(path):
msg = load_email(path)
out = []
out.append(('From', get_from_address(msg)))
out.append(('Subject', get_subject(msg)))


text, html = extract_text_and_html(msg)
out.append(('Text length', len(text)))
out.append(('HTML length', len(html)))


# keywords
kw_text = check_suspicious_keywords(text or '')
kw_html = check_suspicious_keywords(html or '')
out.append(('Suspicious keywords in text', kw_text))
out.append(('Suspicious keywords in html', kw_html))


# links
links = find_html_links(html)
out.append(('Links found (anchor, href)', links))


mismatches = display_vs_actual_mismatch(links)
out.append(('Anchor vs Href mismatches', mismatches))


# header checks
hdr_warnings = header_discrepancy_checks(msg)
out.append(('Header warnings', hdr_warnings))


return out




if __name__ == '__main__':
if len(sys.argv) < 2:
print('Usage: python analyzer.py <email-file.eml>')
sys.exit(2)
path = sys.argv[1]
results = analyze(path)
print('\n=== Phishing Analysis Report (automated heuristics) ===\n')
for k, v in results:
print(f"{k}: {v}\n")
print('Notes: This script uses simple heuristics for educational use only. Review results manually.')
