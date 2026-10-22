"""
Attachment Metadata Scanner — Safe Static File Inspection

Analyzes attachment filenames and metadata for malicious patterns.

⚠️ SAFETY NOTICE:
    This service performs STATIC metadata analysis ONLY.
    It NEVER opens, loads, executes, or parses file binaries.
    It analyzes naming, double extensions, macro types, and dangerous file formats.
"""

import os
import re
import logging
from typing import List, Tuple, Optional
from models.schemas import AttachmentMetadata, AttachmentAnalysisDetail

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# ATTACHMENT RISK DEFINITIONS
# ═══════════════════════════════════════════════════════════════════

# Direct Executables & Scripts (Highest Risk)
DANGEROUS_EXECUTABLE_EXTENSIONS = {
    ".exe": "Windows Executable Program",
    ".scr": "Windows Screensaver Executable (frequently used for stealth malware)",
    ".bat": "Windows Batch Script",
    ".cmd": "Windows Command Script",
    ".vbs": "VBScript Executable Script",
    ".vbe": "VBScript Encrypted Script",
    ".js":  "JavaScript Standalone Executable Script",
    ".jse": "JScript Encrypted Script",
    ".wsf": "Windows Script File",
    ".ps1": "PowerShell Script",
    ".hta": "HTML Application (runs as full-trust desktop application)",
    ".pif": "Program Information File (executable shortcut)",
    ".cpl": "Control Panel Extension Binary",
    ".msi": "Windows Installer Package",
    ".jar": "Java Executable Archive",
}

# Macro-Enabled Documents (High Risk)
MACRO_ENABLED_EXTENSIONS = {
    ".xlsm": "Excel Macro-Enabled Workbook (can execute malicious VBA code)",
    ".docm": "Word Macro-Enabled Document (can execute malicious VBA code)",
    ".pptm": "PowerPoint Macro-Enabled Presentation",
    ".dotm": "Word Macro-Enabled Template",
    ".xltm": "Excel Macro-Enabled Template",
}

# Disk Image & Archive Containers (Medium-to-High Risk when sent via email)
CONTAINER_EXTENSIONS = {
    ".iso": "Disk Image (used by attackers to bypass Mark-of-the-Web security)",
    ".img": "Disk Image Container",
    ".vhd": "Virtual Hard Disk Image",
    ".vhdx": "Virtual Hard Disk Image",
    ".7z":  "Compressed 7-Zip Archive (often used to password-protect malware)",
    ".rar": "Compressed RAR Archive",
    ".cab": "Windows Cabinet File",
}

# Innocent Extensions often spoofed as fake double extensions
DECEPTIVE_PREFIX_EXTENSIONS = [
    "pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png", "jpeg", "csv"
]


class AttachmentAnalyzer:
    """
    Static Attachment Metadata Inspector.
    """

    def analyze_all(
        self,
        attachments: List[AttachmentMetadata]
    ) -> Tuple[List[str], List[AttachmentAnalysisDetail]]:
        """
        Inspects a list of attachments from an email.
        """
        if not attachments:
            return [], []

        filenames = []
        details = []

        for att in attachments:
            filenames.append(att.filename)
            detail = self.analyze_single(att.filename, att.file_size_bytes, att.content_type)
            details.append(detail)

        return filenames, details

    def analyze_single(
        self,
        filename: str,
        file_size_bytes: Optional[int] = None,
        content_type: Optional[str] = None
    ) -> AttachmentAnalysisDetail:
        """
        Performs comprehensive static metadata analysis on a filename and properties.
        """
        reasons: List[str] = []
        score: int = 0
        threat_category = "Safe / Standard Document"

        clean_filename = filename.strip()
        lower_name = clean_filename.lower()

        # ── 1. Check for Deceptive Double Extensions (e.g., invoice.pdf.exe) ──
        # Windows hides known extensions by default, so 'invoice.pdf.exe' looks like 'invoice.pdf'
        double_ext_match = re.search(r'\.(' + '|'.join(DECEPTIVE_PREFIX_EXTENSIONS) + r')\s*\.([a-z0-9]{2,5})$', lower_name)
        
        has_double_ext = False
        if double_ext_match:
            fake_ext = double_ext_match.group(1)
            real_ext = f".{double_ext_match.group(2)}"
            has_double_ext = True
            threat_category = "Deceptive Double Extension"
            score += 35
            reasons.append(
                f"Deceptive double extension detected! The file masquerades as a '.{fake_ext}' document "
                f"but actually ends with the executable extension '{real_ext}'. "
                f"Windows may hide the final extension, tricking the user into executing malware."
            )

        # ── 2. Identify Actual Final Extension ──
        _, final_ext = os.path.splitext(lower_name)

        # ── 3. Check for Direct Executables / Scripts ──
        if final_ext in DANGEROUS_EXECUTABLE_EXTENSIONS:
            threat_category = "Executable Script / Program"
            score += 30
            desc = DANGEROUS_EXECUTABLE_EXTENSIONS[final_ext]
            reasons.append(
                f"Dangerous file extension detected: '{final_ext}' ({desc}). "
                f"Email systems should never accept raw executable scripts as attachments."
            )

        # ── 4. Check for Macro-Enabled Office Documents ──
        elif final_ext in MACRO_ENABLED_EXTENSIONS:
            threat_category = "Macro-Enabled Document"
            score += 25
            desc = MACRO_ENABLED_EXTENSIONS[final_ext]
            reasons.append(
                f"Macro-enabled document detected: '{final_ext}' ({desc}). "
                f"Attackers embed malicious VBA macros in these files to infect systems upon opening."
            )

        # ── 5. Check for Disk Images & High-Risk Containers ──
        elif final_ext in CONTAINER_EXTENSIONS:
            threat_category = "Disk Image / Archive Container"
            score += 18
            desc = CONTAINER_EXTENSIONS[final_ext]
            reasons.append(
                f"Container / Disk image detected: '{final_ext}' ({desc}). "
                f"Attackers use ISO/VHD images to bypass Windows Mark-of-the-Web (MOTW) security controls."
            )

        # ── 6. Check for Obfuscated Space Padding (e.g., 'invoice     .exe') ──
        if re.search(r'\s{3,}\.[a-z0-9]+$', clean_filename, re.IGNORECASE):
            score += 15
            reasons.append(
                "Excessive whitespace padding before extension detected. "
                "Attackers use long space padding to push dangerous extensions out of the user's visible file explorer window."
            )

        # ── 7. Check for Suspicious Phishing Keywords in Filename ──
        suspicious_file_keywords = [
            "payment", "invoice", "receipt", "remittance", "statement", "salary",
            "overdue", "urgent", "swift", "bank_slip", "verification", "wire_transfer"
        ]
        matched_kw = [kw for kw in suspicious_file_keywords if kw in lower_name]
        if matched_kw and score > 0:
            score += 5
            reasons.append(f"Filename contains urgency/financial lure keywords: {', '.join(matched_kw)}")

        # ── 8. Check MIME type mismatch if provided ──
        if content_type:
            if "pdf" in lower_name and "pdf" not in content_type.lower() and content_type != "application/octet-stream":
                score += 10
                reasons.append(f"MIME type mismatch: Filename suggests PDF, but declared MIME is '{content_type}'.")

        # ── Final Risk Mapping ──
        final_score = min(score, 40)
        is_suspicious = final_score > 0
        risk_level = self._score_to_risk(final_score)

        return AttachmentAnalysisDetail(
            filename=clean_filename,
            detected_extension=final_ext or "none",
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            threat_category=threat_category,
            reasons=reasons,
            score_contribution=final_score
        )

    def _score_to_risk(self, score: int) -> str:
        if score == 0:
            return "low"
        elif score <= 15:
            return "medium"
        elif score <= 25:
            return "high"
        else:
            return "critical"


# ═══════════════════════════════════════════════════════════════════
# Global Instance
# ═══════════════════════════════════════════════════════════════════
attachment_analyzer = AttachmentAnalyzer()