"""
M17 Cybersecurity Awareness Training & Quiz Verification Script
"""

import sys
import os

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.training_service import training_service
from models.schemas import QuizSubmissionRequest, QuizSubmissionAnswer
from fastapi.testclient import TestClient
from main import app


def run_tests():
    print("=" * 60)
    print("RUNNING M17 AWARENESS TRAINING & QUIZ TESTS")
    print("=" * 60)

    # ────────────────────────────────────────────────────────
    # 1. Test Training Modules
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.1: Training Modules Listing & Detail ---")
    modules = training_service.list_modules()
    print(f"Total Training Modules: {len(modules)}")
    assert len(modules) >= 5, "Expected at least 5 training modules"

    detail = training_service.get_module_detail("MOD-01")
    assert detail is not None
    print(f"Module MOD-01 Title:   {detail.title}")
    print(f"Red Flags Documented:  {len(detail.red_flag_indicators)}")
    assert len(detail.red_flag_indicators) > 0
    print("[PASS] Test 1.1: Training modules retrieved with comprehensive guidance.")

    # ────────────────────────────────────────────────────────
    # 2. Test Public Quiz & Cheating Prevention
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.2: Public Quiz Generation (Security Check) ---")
    quiz = training_service.get_public_quiz()
    print(f"Total Quiz Questions:  {len(quiz)}")
    assert len(quiz) >= 5

    first_q = quiz[0]
    # Ensure answer key is NOT leaked to public quiz questions
    assert not hasattr(first_q, "correct_option_id")
    print(f"Question 1 Scenario:   '{first_q.title}' ({first_q.scenario_sender})")
    print("[PASS] Test 1.2: Quiz scenarios retrieved with answer keys securely withheld.")

    # ────────────────────────────────────────────────────────
    # 3. Test Quiz Grading Engine (100% Correct Submission)
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.3: Quiz Evaluation (Expert Score) ---")
    perfect_answers = [
        QuizSubmissionAnswer(question_id="Q-01", selected_option_id="phishing"),
        QuizSubmissionAnswer(question_id="Q-02", selected_option_id="legitimate"),
        QuizSubmissionAnswer(question_id="Q-03", selected_option_id="phishing"),
        QuizSubmissionAnswer(question_id="Q-04", selected_option_id="legitimate"),
        QuizSubmissionAnswer(question_id="Q-05", selected_option_id="phishing"),
    ]
    submission_req = QuizSubmissionRequest(user_identifier="test.guardian@university.edu", answers=perfect_answers)
    result = training_service.evaluate_quiz_submission(submission_req)

    print(f"Submission ID:         {result.submission_id}")
    print(f"Score Percentage:      {result.score_percentage}%")
    print(f"Performance Rating:    {result.performance_rating}")
    print(f"Reviews Generated:     {len(result.question_reviews)}")

    assert result.score_percentage == 100.0
    assert "Cyber Guardian" in result.performance_rating
    assert len(result.question_reviews) == 5
    print("[PASS] Test 1.3: Accurate grading and achievement tier assigned for expert submission.")

    # ────────────────────────────────────────────────────────
    # 4. Test Quiz Grading Engine (Lower Score & Remediation Guidance)
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.4: Quiz Evaluation (Remediation Feedback) ---")
    vulnerable_answers = [
        QuizSubmissionAnswer(question_id="Q-01", selected_option_id="legitimate"),  # wrong
        QuizSubmissionAnswer(question_id="Q-02", selected_option_id="legitimate"),  # correct
        QuizSubmissionAnswer(question_id="Q-03", selected_option_id="legitimate"),  # wrong
        QuizSubmissionAnswer(question_id="Q-04", selected_option_id="legitimate"),  # correct
        QuizSubmissionAnswer(question_id="Q-05", selected_option_id="legitimate"),  # wrong
    ]
    vuln_req = QuizSubmissionRequest(user_identifier="student@university.edu", answers=vulnerable_answers)
    vuln_result = training_service.evaluate_quiz_submission(vuln_req)

    print(f"Vulnerable Score:      {vuln_result.score_percentage}%")
    print(f"Performance Rating:    {vuln_result.performance_rating}")
    print(f"Recommendations:       {vuln_result.recommendations}")

    assert vuln_result.score_percentage < 60.0
    assert "Vulnerable" in vuln_result.performance_rating
    assert len(vuln_result.recommendations) > 0
    print("[PASS] Test 1.4: Appropriate pedagogical recommendations returned for low scores.")

    # ────────────────────────────────────────────────────────
    # 5. Test FastAPI HTTP Endpoints
    # ────────────────────────────────────────────────────────
    print("\n--- Test 1.5: FastAPI Training & Quiz Endpoints ---")
    client = TestClient(app)

    # 5.1 GET /api/training/modules
    resp_mod = client.get("/api/training/modules")
    print(f"GET /api/training/modules: {resp_mod.status_code}")
    assert resp_mod.status_code == 200
    assert len(resp_mod.json()) >= 5

    # 5.2 GET /api/training/modules/MOD-01
    resp_mod_det = client.get("/api/training/modules/MOD-01")
    print(f"GET /api/training/modules/MOD-01: {resp_mod_det.status_code}")
    assert resp_mod_det.status_code == 200
    assert resp_mod_det.json()["module_id"] == "MOD-01"

    # 5.3 GET /api/training/quiz
    resp_quiz = client.get("/api/training/quiz")
    print(f"GET /api/training/quiz: {resp_quiz.status_code}")
    assert resp_quiz.status_code == 200
    assert len(resp_quiz.json()) >= 5

    # 5.4 POST /api/training/quiz/submit
    submit_payload = submission_req.model_dump(mode="json")
    resp_sub = client.post("/api/training/quiz/submit", json=submit_payload)
    print(f"POST /api/training/quiz/submit: {resp_sub.status_code}")
    assert resp_sub.status_code == 200
    assert resp_sub.json()["score_percentage"] == 100.0

    print("\n" + "=" * 60)
    print("ALL M17 AWARENESS TRAINING & QUIZ TESTS PASSED! [SUCCESS]")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()