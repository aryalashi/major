#!/usr/bin/env python3
"""Patch the detection engine to properly classify specific attacks"""

import re

# Read the original file
with open('advanced_detection_engine.py', 'r') as f:
    content = f.read()

# Fix 1: Make sure payload attacks are properly labeled
# Look for where SQL injection is returned
old_sql = "'attack': 'SQL Injection'"
new_sql = "'attack': 'SQL Injection Attack'"

if old_sql in content:
    content = content.replace(old_sql, new_sql)
    print(f"✓ Fixed SQL injection label")

# Fix 2: Ensure XSS is properly labeled
old_xss = "'attack': 'XSS Attack'"
new_xss = "'attack': 'Cross-Site Scripting (XSS)'"

if old_xss in content:
    content = content.replace(old_xss, new_xss)
    print(f"✓ Fixed XSS label")

# Fix 3: Ensure Command Injection is labeled
old_cmd = "'attack': 'Command Injection'"
new_cmd = "'attack': 'Command Injection Attack'"

if old_cmd in content:
    content = content.replace(old_cmd, new_cmd)
    print(f"✓ Fixed command injection label")

# Fix 4: Fix the targeted attack pattern detection
# The issue is that _detect_behavioral_attacks is always triggering
# Let's make it less sensitive or remove the generic "Targeted Attack Pattern"

# Find the _detect_behavioral_attacks method and modify the confidence threshold
pattern = r"if is_consistent, conf = self\._detect_consistent_target\(pkt_dict\)\n            if is_consistent:\n                alerts\.append\(\{\n                    'attack': 'Targeted Attack Pattern',\n                    'severity': 'HIGH',\n                    'layer': 'Behavioral',\n                    'confidence': conf\n                \}\)"

# Increase the threshold to only trigger on very high confidence
replacement = r"if is_consistent, conf = self._detect_consistent_target(pkt_dict)\n            # Only trigger if confidence is very high (90%+)\n            if is_consistent and conf >= 90:\n                alerts.append({\n                    'attack': 'Targeted Attack Pattern',\n                    'severity': 'HIGH',\n                    'layer': 'Behavioral',\n                    'confidence': conf\n                })"

if re.search(pattern, content):
    content = re.sub(pattern, replacement, content)
    print(f"✓ Increased threshold for 'Targeted Attack Pattern'")

# Write the patched content back
with open('advanced_detection_engine.py', 'w') as f:
    f.write(content)

print("\n✓ Patch applied! Restart your tests.")
