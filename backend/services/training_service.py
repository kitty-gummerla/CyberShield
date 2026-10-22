"""
Cybersecurity Awareness Training & Quiz Service (Milestone 17)

Provides:
1. Structured training curriculum on modern cyber threats.
2. Interactive scenario-based quiz bank (Phishing vs. Legitimate).
3. Automated grading, indicator-based feedback, and awareness scoring.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from models.schemas import (
    TrainingModuleSummary,
    TrainingModuleDetail,
    QuizQuestionPublic,
    QuizQuestionOption,
    QuizSubmissionRequest,
    QuizResultResponse,
    QuestionReviewDetail
)


# ═══════════════════════════════════════════════════════════════════
# CURRICULUM: CYBERSECURITY TRAINING MODULES
# ═══════════════════════════════════════════════════════════════════

TRAINING_MODULES: Dict[str, Dict[str, Any]] = {
    "MOD-01": {
        "module_id": "MOD-01",
        "title": "Social Engineering & Psychological Triggers",
        "category": "Human Factors",
        "difficulty": "Beginner",
        "estimated_minutes": 5,
        "description": "Understand how cyber attackers exploit human emotions like urgency, fear, curiosity, and authority.",
        "icon": "Brain",
        "attack_mechanism": (
            "Phishing rarely relies solely on technical bugs. Attackers craft messages that trigger emotional shortcuts: "
            "fear of account suspension, urgency around deadlines, or false authority from 'executives' or 'IT staff', "
            "causing victims to bypass their critical judgment."
        ),
        "real_world_example": (
            "An email impersonating the CEO demands an immediate wire transfer for an 'emergency corporate acquisition', "
            "warning the employee not to call or speak to anyone because the deal is confidential."
        ),
        "red_flag_indicators": [
            "Artificial urgency: 'Account terminated within 2 hours!'",
            "Demands to bypass standard approval channels.",
            "Generic or mismatched greetings ('Dear Customer' vs. your name).",
            "High emotional pressure to act before verifying."
        ],
        "defense_checklist": [
            "Always slow down: legitimate emergencies are never resolved exclusively via panic emails.",
            "Verify requests out-of-band using a known company phone number or in-person check.",
            "Never share OTPs, MFA codes, or passwords over email."
        ]
    },
    "MOD-02": {
        "module_id": "MOD-02",
        "title": "Deceptive URLs & Lookalike Domains",
        "category": "Network & Web",
        "difficulty": "Intermediate",
        "estimated_minutes": 7,
        "description": "Learn to inspect hyperlinks, recognize typosquatting, and unmask fraudulent login portals.",
        "icon": "Globe",
        "attack_mechanism": (
            "Attackers register domains that look identical to trusted services using typosquatting "
            "(e.g., 'paypa1.com' or 'secure-bank-login.xyz') or deceptive subdomains "
            "(e.g., 'paypal.com.attacker-domain.net'). When clicked, they present cloned credential-harvesting forms."
        ),
        "real_world_example": (
            "A message claims you received an encrypted document. The button says 'View Document on OneDrive', "
            "but the underlying URL actually points to 'http://login.onedrive-share-doc.top/auth'."
        ),
        "red_flag_indicators": [
            "Domain name mismatches between displayed text and actual URL target.",
            "Use of unusual Top-Level Domains (TLDs) like .xyz, .top, .work for official services.",
            "Hyphenated brand names (e.g., 'apple-support-verify.com').",
            "Subdomain deception where the real domain is at the end of the host string."
        ],
        "defense_checklist": [
            "Hover before clicking: check the destination URL displayed in your browser's bottom status bar.",
            "Navigate directly: instead of clicking email links, type the official address directly into your browser.",
            "Bookmark verified corporate and banking portals."
        ]
    },
    "MOD-03": {
        "module_id": "MOD-03",
        "title": "Weaponized Attachments & Macro Malware",
        "category": "Endpoint Defense",
        "difficulty": "Intermediate",
        "estimated_minutes": 8,
        "description": "Examine how malicious files disguise themselves and execute code to compromise local endpoints.",
        "icon": "FileWarning",
        "attack_mechanism": (
            "Attackers attach weaponized office files (.xlsm, .docm) containing malicious Visual Basic macros, "
            "or use double extensions (.pdf.exe) on Windows systems where known file extensions are hidden by default. "
            "Opening the file triggers background script execution."
        ),
        "real_world_example": (
            "An invoice named 'Overdue_Statement_August.xlsm' contains a blurred image and prompts: "
            "'Click Enable Content / Enable Macros to decrypt your confidential salary data.'"
        ),
        "red_flag_indicators": [
            "Macro-enabled extensions: .xlsm, .docm, .dotm.",
            "Concealed executables using double extensions (e.g., invoice.pdf.exe).",
            "Compressed archives (.zip, .rar, .iso) containing script files (.js, .vbs, .bat).",
            "Prompts inside the document asking you to disable protected view."
        ],
        "defense_checklist": [
            "NEVER enable macros or content on documents received from external or unexpected sources.",
            "Configure Windows to always display file extensions ('File name extensions' checkbox in Explorer).",
            "Upload suspicious files to a secure sandbox or verify with IT security before opening."
        ]
    },
    "MOD-04": {
        "module_id": "MOD-04",
        "title": "Email Headers & Authentication (SPF, DKIM, DMARC)",
        "category": "Email Security",
        "difficulty": "Advanced",
        "estimated_minutes": 10,
        "description": "Understand technical email headers and how SPF, DKIM, and DMARC prevent sender spoofing.",
        "icon": "ShieldCheck",
        "attack_mechanism": (
            "The basic SMTP protocol does not verify sender addresses, allowing attackers to forge the 'From:' field. "
            "Modern email security uses SPF (IP whitelists), DKIM (cryptographic signatures), and DMARC (policy enforcement) "
            "to prove the authenticity of the sending mail server."
        ),
        "real_world_example": (
            "An attacker sends an email displaying 'From: support@paypal.com', but the Return-Path header shows "
            "'bounce@phish-relay.net' and the Received-SPF check failed because the sending IP is not authorized by PayPal."
        ),
        "red_flag_indicators": [
            "Authentication-Results header indicates 'spf=fail' or 'dkim=fail'.",
            "Mismatched 'From:' display address versus technical 'Return-Path' or 'Reply-To' address.",
            "Email received from an IP address in a completely unrelated country/ASN."
        ],
        "defense_checklist": [
            "Inspect raw headers when in doubt ('Show Original' in Gmail, 'View Message Details' in Outlook).",
            "Check that Authentication-Results report 'spf=pass' and 'dkim=pass'.",
            "Report spoofed emails to your mail administrator to enforce strict DMARC rejection rules."
        ]
    },
    "MOD-05": {
        "module_id": "MOD-05",
        "title": "Business Email Compromise (BEC) & Vendor Fraud",
        "category": "Corporate Security",
        "difficulty": "Advanced",
        "estimated_minutes": 6,
        "description": "Recognize targeted, non-malware spear-phishing that targets finance, payroll, and executives.",
        "icon": "DollarSign",
        "attack_mechanism": (
            "BEC attacks rarely contain malicious links or attachments, allowing them to slip past simple filters. "
            "Instead, attackers use compromised vendor accounts or lookalike domains to request invoice bank changes "
            "or direct-deposit redirections."
        ),
        "real_world_example": (
            "A supplier's accountant appears to write: 'Our banking provider has changed. Please update our account number "
            "on file before paying tomorrow's $45,000 invoice.'"
        ),
        "red_flag_indicators": [
            "Last-minute requests to change bank account details or routing numbers.",
            "Requests from executives claiming to be in meetings where they cannot be called.",
            "Pressure to expedite wire payments without standard secondary approval."
        ],
        "defense_checklist": [
            "Mandate two-person verification for any change to supplier banking details.",
            "Perform out-of-band voice confirmation using previously established contact numbers.",
            "Never reply directly to the email requesting the payment redirection."
        ]
    }
}


# ═══════════════════════════════════════════════════════════════════
# QUIZ BANK: REALISTIC PHISHING VS LEGITIMATE SCENARIOS
# ═══════════════════════════════════════════════════════════════════

QUIZ_QUESTIONS_INTERNAL: List[Dict[str, Any]] = [
    {
        "question_id": "Q-01",
        "title": "Account Access Alert",
        "category": "Credential Harvesting",
        "difficulty": "Beginner",
        "scenario_sender": "security-alert@paypal-update.xyz",
        "scenario_subject": "URGENT: Unauthorized Account Access Detected",
        "scenario_body": (
            "Dear Customer, We detected an unauthorized login attempt from IP 185.220.101.5. "
            "Your account has been temporarily restricted. Click the secure verification portal below "
            "and confirm your password and 6-digit OTP immediately: http://paypal-verification.fake-security.xyz/login"
        ),
        "has_attachment": False,
        "attachment_name": None,
        "correct_option_id": "phishing",
        "explanation": (
            "This is a classic credential-harvesting phishing attack. It uses artificial urgency (temporary restriction), "
            "asks for sensitive OTP authentication codes, and directs the user to a suspicious lookalike domain (.xyz)."
        ),
        "red_flags": [
            "Sender domain 'paypal-update.xyz' is not the official paypal.com.",
            "Link points to an unverified third-party domain 'fake-security.xyz'.",
            "Requests your password and 6-digit OTP code."
        ]
    },
    {
        "question_id": "Q-02",
        "title": "Semester Examination Timetable",
        "category": "Academic Notice",
        "difficulty": "Beginner",
        "scenario_sender": "registrar@university.edu",
        "scenario_subject": "Fall Semester Final Examination Schedule",
        "scenario_body": (
            "Dear Students, The final examination schedule has been officially released on the university student portal. "
            "Please review your exam hall allocations and timetable as usual. Best regards, Office of the Registrar."
        ),
        "has_attachment": False,
        "attachment_name": None,
        "correct_option_id": "legitimate",
        "explanation": (
            "This is a legitimate announcement. The sender address is an authentic university .edu domain, "
            "it contains no suspicious links, makes no urgent demands, and asks for no credentials."
        ),
        "red_flags": []
    },
    {
        "question_id": "Q-03",
        "title": "Corporate Bonus Calculation Spreadsheet",
        "category": "Malicious Attachment",
        "difficulty": "Intermediate",
        "scenario_sender": "payroll-update@company-services.com",
        "scenario_subject": "Q3 Salary Adjustment & Bonus Calculation",
        "scenario_body": (
            "Hello Team, Please review the attached corporate spreadsheet regarding updated Q3 salary structures. "
            "Enable macros when prompted to generate your personalized tax projection."
        ),
        "has_attachment": True,
        "attachment_name": "Q3_Salary_Breakdown.xlsm",
        "correct_option_id": "phishing",
        "explanation": (
            "This is a macro-malware delivery email. The attachment is a macro-enabled Excel sheet (.xlsm), "
            "and the body explicitly instructs the user to enable macros, which executes malicious code on the system."
        ),
        "red_flags": [
            "Macro-enabled attachment extension (.xlsm).",
            "Explicit instruction to 'Enable macros' to view content.",
            "Generic sender domain 'company-services.com'."
        ]
    },
    {
        "question_id": "Q-04",
        "title": "GitHub Password Reset Confirmation",
        "category": "Standard Notification",
        "difficulty": "Intermediate",
        "scenario_sender": "support@github.com",
        "scenario_subject": "[GitHub] Please reset your password",
        "scenario_body": (
            "We heard that you lost your GitHub password. Sorry about that! "
            "You can use the following link to reset your password within the next 24 hours: "
            "https://github.com/password_reset/auth_token_8849201948271\n"
            "If you did not request a password reset, you can safely ignore this email."
        ),
        "has_attachment": False,
        "attachment_name": None,
        "correct_option_id": "legitimate",
        "explanation": (
            "This is a standard transactional reset email initiated by the user. The link points strictly to the official "
            "https://github.com domain over HTTPS, and the email clearly states you can ignore it if you did not request it."
        ),
        "red_flags": []
    },
    {
        "question_id": "Q-05",
        "title": "Final Demand Overdue Invoice",
        "category": "Concealed Executable",
        "difficulty": "Advanced",
        "scenario_sender": "billing-support@fake-quickbooks.net",
        "scenario_subject": "Overdue Invoice Notice — Final Demand",
        "scenario_body": (
            "ATTENTION: This is your final demand notice. Failure to settle the outstanding balance of $1,450.00 "
            "immediately will result in legal proceedings. View the attached PDF invoice for remittance instructions."
        ),
        "has_attachment": True,
        "attachment_name": "Invoice_98412_Overdue.pdf.exe",
        "correct_option_id": "phishing",
        "explanation": (
            "This is an executable malware attack using a deceptive double extension (.pdf.exe). "
            "On standard systems, the .exe extension is masked, tricking the user into running an executable program."
        ),
        "red_flags": [
            "Dangerous double extension: 'Invoice_98412_Overdue.pdf.exe'.",
            "Threats of immediate legal action to induce panic.",
            "Spoofed QuickBooks billing sender address."
        ]
    }
]


class TrainingService:
    """
    Manages educational training curriculum and quiz evaluation.
    """

    def list_modules(self) -> List[TrainingModuleSummary]:
        """Returns summaries of all available awareness training modules."""
        summaries = []
        for mod in TRAINING_MODULES.values():
            summaries.append(TrainingModuleSummary(
                module_id=mod["module_id"],
                title=mod["title"],
                category=mod["category"],
                difficulty=mod["difficulty"],
                estimated_minutes=mod["estimated_minutes"],
                description=mod["description"],
                icon=mod["icon"]
            ))
        return summaries

    def get_module_detail(self, module_id: str) -> Optional[TrainingModuleDetail]:
        """Returns complete educational content for a specific training module."""
        mod = TRAINING_MODULES.get(module_id)
        if not mod:
            return None
        return TrainingModuleDetail(**mod)

    def get_public_quiz(self) -> List[QuizQuestionPublic]:
        """
        Returns all quiz scenarios with answer keys safely withheld.
        """
        public_questions = []
        standard_options = [
            QuizQuestionOption(option_id="phishing", text="⚠️ Phishing / Suspicious Email"),
            QuizQuestionOption(option_id="legitimate", text="✅ Legitimate / Safe Email")
        ]

        for q in QUIZ_QUESTIONS_INTERNAL:
            public_questions.append(QuizQuestionPublic(
                question_id=q["question_id"],
                title=q["title"],
                category=q["category"],
                difficulty=q["difficulty"],
                scenario_sender=q["scenario_sender"],
                scenario_subject=q["scenario_subject"],
                scenario_body=q["scenario_body"],
                has_attachment=q["has_attachment"],
                attachment_name=q["attachment_name"],
                options=standard_options
            ))
        return public_questions

    def evaluate_quiz_submission(self, submission: QuizSubmissionRequest) -> QuizResultResponse:
        """
        Grades user answers, calculates awareness score, and generates detailed educational feedback.
        """
        submission_id = f"QUIZ-{uuid.uuid4().hex[:8].upper()}"
        question_map = {q["question_id"]: q for q in QUIZ_QUESTIONS_INTERNAL}

        user_answers_map = {a.question_id: a.selected_option_id.lower().strip() for a in submission.answers}
        total_questions = len(QUIZ_QUESTIONS_INTERNAL)
        correct_count = 0
        reviews: List[QuestionReviewDetail] = []

        for q_id, q_data in question_map.items():
            user_choice = user_answers_map.get(q_id, "unanswered")
            correct_choice = q_data["correct_option_id"]
            is_correct = (user_choice == correct_choice)

            if is_correct:
                correct_count += 1

            reviews.append(QuestionReviewDetail(
                question_id=q_id,
                title=q_data["title"],
                user_answer=user_choice,
                correct_answer=correct_choice,
                is_correct=is_correct,
                explanation=q_data["explanation"],
                red_flags=q_data["red_flags"]
            ))

        score_pct = round((correct_count / total_questions) * 100, 1)

        # Performance Rating & Feedback
        if score_pct >= 80:
            rating = "Cyber Guardian (Expert)"
            summary = "Outstanding security awareness! You identified critical red flags and correctly classified safe emails."
            recommendations = [
                "Continue practicing your skills by reviewing emerging social engineering trends.",
                "Serve as a security champion in your team or study group."
            ]
        elif score_pct >= 60:
            rating = "Security Aware (Proficient)"
            summary = "Good security foundation, but you were deceived by subtle attack vectors."
            recommendations = [
                "Pay closer attention to attachment extensions (.xlsm and .exe).",
                "Always check destination URLs before entering credentials."
            ]
        else:
            rating = "Vulnerable to Social Engineering (Needs Practice)"
            summary = "Your score indicates vulnerability to modern phishing attacks. Review the training modules."
            recommendations = [
                "Complete Training Module MOD-01 on Social Engineering Psychology.",
                "Complete Training Module MOD-03 on Weaponized Attachments.",
                "Retake the quiz to reinforce your defensive reflexes."
            ]

        return QuizResultResponse(
            submission_id=submission_id,
            total_questions=total_questions,
            correct_count=correct_count,
            score_percentage=score_pct,
            performance_rating=rating,
            summary=summary,
            recommendations=recommendations,
            question_reviews=reviews,
            submitted_at=datetime.utcnow()
        )


# ═══════════════════════════════════════════════════════════════════
# Global Training Service Instance
# ═══════════════════════════════════════════════════════════════════
training_service = TrainingService()