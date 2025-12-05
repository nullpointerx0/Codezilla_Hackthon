import os
from typing import Dict, List, Optional
from functools import lru_cache

class LLMAttackDetector:
    def __init__(self) -> None:
        self.available = False
        self.class_labels = ["Normal", "Attempted Attack", "Likely Successful Attack"]
        self.attack_labels = [
            "SQL Injection",
            "XSS",
            "Command Injection",
            "SSRF",
            "Directory Traversal",
            "Credential Stuffing",
        ]
        self.threshold = float(os.getenv("LLM_ATTACK_THRESHOLD", "0.7"))
        model_name = os.getenv("LLM_MODEL", "MoritzLaurer/deberta-v3-large-zeroshot-v2")
        hypothesis_cls = os.getenv("LLM_HYPOTHESIS_CLS", "This URL is {label}.")
        hypothesis_attack = os.getenv("LLM_HYPOTHESIS_ATTACK", "The attack type is {label}.")
        try:
            from transformers import pipeline
            self._pipe_cls = pipeline("zero-shot-classification", model=model_name, hypothesis_template=hypothesis_cls)
            self._pipe_attack = pipeline("zero-shot-classification", model=model_name, hypothesis_template=hypothesis_attack)
            self.available = True
        except Exception:
            self.available = False

    @lru_cache(maxsize=2048)
    def _classify_text(self, text: str):
        return self._pipe_cls(text, candidate_labels=self.class_labels, multi_label=False)

    @lru_cache(maxsize=2048)
    def _attack_text(self, text: str):
        return self._pipe_attack(text, candidate_labels=self.attack_labels, multi_label=True)

    def analyze_url(self, url: str, status_code: int = 0, method: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> Dict:
        if not self.available:
            return {"classification": "Normal", "attack_type": None, "severity": "Low", "indicators": []}
        text = str(url or "")
        if not text:
            return {"classification": "Normal", "attack_type": None, "severity": "Low", "indicators": []}
        extra = []
        m = str(method or '').upper().strip()
        if m:
            extra.append(f"METHOD:{m}")
        if headers:
            for hk, hv in list(headers.items()):
                hk_s = str(hk or '')
                hv_s = str(hv or '')
                if hk_s and hv_s:
                    extra.append(f"H:{hk_s}:{hv_s[:100]}")
        text2 = text if not extra else (text + " " + " ".join(extra))
        class_res = self._classify_text(text2)
        attack_res = self._attack_text(text2)
        cls_label = class_res.get("labels", [self.class_labels[0]])[0]
        chosen_attacks: List[str] = []
        indicators: List[str] = []
        labels = attack_res.get("labels", [])
        scores = attack_res.get("scores", [])
        for i, lab in enumerate(labels):
            s = float(scores[i]) if i < len(scores) else 0.0
            if s >= self.threshold:
                chosen_attacks.append(lab)
                indicators.append(f"{lab}: {round(s, 3)}")
        attack_type = None if not chosen_attacks else ", ".join(chosen_attacks)
        try:
            status_code = int(status_code) if status_code is not None else 0
        except Exception:
            status_code = 0
        if attack_type is None:
            classification = "Normal"
            severity = "Low"
        else:
            if status_code >= 200 and status_code < 300:
                classification = "Likely Successful Attack"
                severity = "High"
            elif status_code >= 400 and status_code < 500:
                classification = "Attempted Attack"
                severity = "Medium"
            elif status_code >= 500:
                classification = "Likely Successful Attack"
                severity = "High"
            else:
                classification = cls_label if cls_label in self.class_labels else "Attempted Attack"
                severity = "Medium" if classification != "Normal" else "Low"
            if "," in attack_type:
                severity = "High"
                if classification == "Attempted Attack":
                    classification = "Likely Successful Attack"
        return {"classification": classification, "attack_type": attack_type, "severity": severity, "indicators": indicators}
