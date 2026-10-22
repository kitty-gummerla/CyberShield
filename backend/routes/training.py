"""
Cybersecurity Awareness Training & Quiz Routes (Milestone 17)

Endpoints:
1. GET  /api/training/modules         -> List all awareness training topics
2. GET  /api/training/modules/{id}    -> Fetch detailed content for a module
3. GET  /api/training/quiz            -> Retrieve interactive quiz questions (safe view)
4. POST /api/training/quiz/submit     -> Grade quiz answers & return performance report
"""

from fastapi import APIRouter, HTTPException
from typing import List
import logging

from models.schemas import (
    TrainingModuleSummary,
    TrainingModuleDetail,
    QuizQuestionPublic,
    QuizSubmissionRequest,
    QuizResultResponse
)
from services.training_service import training_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/training", tags=["Cybersecurity Awareness Training & Quiz"])


# ─────────────────────────────────────────────
# 1. LIST ALL TRAINING MODULES
# ─────────────────────────────────────────────
@router.get(
    "/modules",
    response_model=List[TrainingModuleSummary],
    summary="List all awareness training modules",
    description="Returns summaries of all security awareness lessons for dashboard and training listings."
)
async def list_training_modules():
    return training_service.list_modules()


# ─────────────────────────────────────────────
# 2. GET TRAINING MODULE DETAIL
# ─────────────────────────────────────────────
@router.get(
    "/modules/{module_id}",
    response_model=TrainingModuleDetail,
    summary="Get full training module content",
    description="Returns detailed curriculum content, real-world examples, red flags, and defense checklists."
)
async def get_module_detail(module_id: str):
    detail = training_service.get_module_detail(module_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Training module '{module_id}' not found.")
    return detail


# ─────────────────────────────────────────────
# 3. GET INTERACTIVE QUIZ QUESTIONS
# ─────────────────────────────────────────────
@router.get(
    "/quiz",
    response_model=List[QuizQuestionPublic],
    summary="Get phishing detection quiz questions",
    description="Returns realistic email scenario questions. Answer keys are withheld for fair evaluation."
)
async def get_quiz():
    return training_service.get_public_quiz()


# ─────────────────────────────────────────────
# 4. SUBMIT AND GRADE QUIZ
# ─────────────────────────────────────────────
@router.post(
    "/quiz/submit",
    response_model=QuizResultResponse,
    summary="Grade quiz submission and get awareness score",
    description="Evaluates user answers, computes score percentage, assigns a performance badge, and returns detailed explanations."
)
async def submit_quiz(submission: QuizSubmissionRequest):
    try:
        result = training_service.evaluate_quiz_submission(submission)
        return result
    except Exception as e:
        logger.error(f"Quiz grading error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Quiz evaluation failed: {str(e)}")