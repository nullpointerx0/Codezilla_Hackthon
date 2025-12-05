import os
import re
from typing import Dict, List, Optional

class AttackDetector:
    """
    Detects various URL-based attacks using regex patterns.
    """
    
    def __init__(self):
        self.mode = os.getenv("DETECTOR_MODE", "regex").lower()
        self.use_llm = self.mode in ("llm", "ensemble") or os.getenv("USE_LLM_DETECTOR", "false").lower() in ("1", "true", "yes")
        self.llm = None
        if self.use_llm:
            try:
                from llm_detector import LLMAttackDetector
                self.llm = LLMAttackDetector()
                if not self.llm.available:
                    self.use_llm = False
            except Exception:
                self.use_llm = False
        # SQL 
        self.sql_patterns = [
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\")",
            r"(?i)(';?\s*(--|#|\/\*|\*\/)|';\s*(drop|delete|insert|update|create|alter))",
            r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)",
            r"(?i)(\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+)",
            r"(?i)(\badmin\b\s*'?\s*or\s*'?\s*'?\s*=\s*'?)",
            r"(?i)(\'\s*(or|and)\s+.*\s*=\s*.*)",
            r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
        ]
        
        # XSS 
        self.xss_patterns = [
            r"(?i)(<script[^>]*>.*?</script>)",
            r"(?i)(javascript\s*:)",
            r"(?i)(on\w+\s*=\s*['\"][^'\"]*['\"])",
            r"(?i)(<iframe[^>]*>|<embed[^>]*>|<object[^>]*>|<img[^>]*onerror)",
            r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
            r"(?i)(eval\s*\(|expression\s*\()",
            r"(?i)(<svg[^>]*onload|<body[^>]*onload)",
            r"(?i)(data:text/html|vbscript:|livescript:)",
        ]
        
        # Command 
        self.command_injection_patterns = [
            r"(?i)(;\s*(rm\s+-rf|cat\s+/etc/passwd|ls\s+-la|pwd|whoami|id))",
            r"(?i)(\|\s*(rm|cat|ls|nc|wget|curl|bash|sh))",
            r"(?i)(`.*(rm|cat|ls|nc|wget|curl|bash|sh).*`)",
            r"(?i)(\$\(.*(rm|cat|ls|nc|wget|curl|bash|sh).*\))",
            r"(?i)(&&\s*(rm|cat|ls|nc|wget|curl|bash|sh))",
            r"(?i)(\|\|\s*(rm|cat|ls|nc|wget|curl|bash|sh))",
            r"(?i)(\bexec\s+|\bsystem\s+|\bshell_exec\s+|\bpassthru\s+)",
            r"(?i)(/bin/(sh|bash|zsh|csh)|cmd\.exe|powershell)",
        ]
        
        # SSRF 
        self.ssrf_patterns = [
            r"(?i)(http://(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254))",
            r"(?i)(http://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.))",
            r"(?i)(file://|gopher://|dict://|ldap://)",
            r"(?i)(http://\[::1\]|http://\[::\]|http://0x7f\.0x0\.0x0\.0x1)",
            r"(?i)(metadata\.googleapis\.com|169\.254\.169\.254)",
            r"(?i)(http://.*@.*@.*)",
        ]
        
        # Directory Traversal 
        self.directory_traversal_patterns = [
            r"(\.\./){2,}",
            r"(\.\.\\\\){2,}",
            r"(?i)(\.\.%2f|\.\.%5c|\.\.%252f|\.\.%255c)",
            r"(?i)(/etc/passwd|/etc/shadow|/windows/system32|/proc/self)",
            r"(?i)(\.\.%c0%af|\.\.%c1%9c)",
            r"(?i)(\.\./\.\./\.\./\.\./)",
        ]
        
        # Credential Stuffing 
        self.credential_stuffing_patterns = [
            r"(?i)(/login|/signin|/auth|/authenticate).*password",
            r"(?i)(password=.*(admin|123456|password|qwerty|letmein|welcome|monkey|1234567890))",
            r"(?i)(username=.*&password=.*&.*password=)",
            r"(?i)(login.*failed|authentication.*failed|invalid.*credentials)",
        ]
        
        
        self.compiled_patterns = {
            'SQL Injection': [re.compile(p) for p in self.sql_patterns],
            'XSS': [re.compile(p) for p in self.xss_patterns],
            'Command Injection': [re.compile(p) for p in self.command_injection_patterns],
            'SSRF': [re.compile(p) for p in self.ssrf_patterns],
            'Directory Traversal': [re.compile(p) for p in self.directory_traversal_patterns],
            'Credential Stuffing': [re.compile(p) for p in self.credential_stuffing_patterns],
        }
    
    def analyze_url(self, url: str, status_code: int = 0, method: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> Dict:
        """
        Analyze a URL for potential attacks.
        """
        if self.use_llm and self.llm and self.mode == "llm":
            return self.llm.analyze_url(url, status_code, method, headers)
        
        if url is None:
            url = ''
        else:
            url = str(url)
        
        if not url or url == 'None':
            return {
                'classification': 'Normal',
                'attack_type': None,
                'severity': 'Low',
                'indicators': []
            }
        
        # Ensure status_code is an integer
        try:
            status_code = int(status_code) if status_code is not None else 0
        except (ValueError, TypeError):
            status_code = 0

        detected_attacks = []
        indicators = []

        m = str(method or '').upper().strip()
        if m in ("TRACE", "TRACK"):
            detected_attacks.append("Suspicious Method")
            indicators.append(f"Method: {m}")

        header_map = headers or {}
        for hk, hv in list(header_map.items()):
            hk_s = str(hk or '')
            hv_s = str(hv or '')
            if not hk_s and not hv_s:
                continue
            if 'user-agent' in hk_s.lower():
                ua = hv_s.lower()
                if ('sqlmap' in ua) or ('nikto' in ua) or ('acunetix' in ua) or ('nmap' in ua) or ('dirbuster' in ua):
                    detected_attacks.append('Scanner/Probe')
                    indicators.append(f"User-Agent: {hv_s[:50]}")
                if ('curl' in ua) or ('wget' in ua):
                    detected_attacks.append('Command Injection Probe')
                    indicators.append(f"User-Agent: {hv_s[:50]}")
            if 'referer' in hk_s.lower():
                ref = hv_s.lower()
                if ('javascript:' in ref) or ('<script' in ref):
                    detected_attacks.append('XSS')
                    indicators.append('Header Referer contains script')
            if 'x-forwarded-for' in hk_s.lower():
                if ('127.0.0.1' in hv_s) or ('localhost' in hv_s):
                    detected_attacks.append('SSRF')
                    indicators.append('X-Forwarded-For local IP')
            if 'cookie' in hk_s.lower():
                if '() { :; };' in hv_s:
                    detected_attacks.append('Command Injection')
                    indicators.append('Shellshock pattern in Cookie')
        
        # Check each attack type
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                try:
                    match = pattern.search(url)
                    if match and match.group(0):
                        match_str = str(match.group(0))[:50]
                        detected_attacks.append(attack_type)
                        indicators.append(f"{attack_type}: {match_str}")
                        break
                except (AttributeError, TypeError, ValueError):
                    continue
        
        if self.use_llm and self.llm and self.mode == "ensemble":
            llm_res = self.llm.analyze_url(url, status_code, method, headers)
            if llm_res.get('attack_type'):
                for t in str(llm_res['attack_type']).split(', '):
                    if t and t not in detected_attacks:
                        detected_attacks.append(t)
                indicators.extend(llm_res.get('indicators', []))

        if not detected_attacks:
            classification = 'Normal'
            severity = 'Low'
            attack_type = None
        else:
            if status_code >= 200 and status_code < 300:
                classification = 'Likely Successful Attack'
                severity = 'High'
            elif status_code >= 400 and status_code < 500:
                classification = 'Attempted Attack'
                severity = 'Medium'
            elif status_code >= 500:
                classification = 'Likely Successful Attack'
                severity = 'High'
            else:
                classification = 'Attempted Attack'
                severity = 'Medium'
            if len(detected_attacks) > 1:
                severity = 'High'
                if classification == 'Attempted Attack':
                    classification = 'Likely Successful Attack'
            attack_type = ', '.join(detected_attacks)
        
        return {
            'classification': classification,
            'attack_type': attack_type,
            'severity': severity,
            'indicators': indicators
        }
