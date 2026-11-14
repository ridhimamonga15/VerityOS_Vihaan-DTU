"""
Analyze route — POST /api/analyze — Member 3.

Accepts a user query, validates the request, generates a unique task_id,
invokes the analysis pipeline, and returns the structured result.
"""

from __future__ import annotations

import uuid
import logging
import traceback

from fastapi import APIRouter, Depends, HTTPException

from backend.models.requests import AnalyzeRequest
from backend.models.responses import AnalyzeResponse, ErrorResponse
from backend.pipeline import run_pipeline
from backend.dependencies import get_user_for_analyze

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyse a user query",
    description=(
        "Accepts a natural-language query, runs it through the VerityOS "
        "analysis pipeline (Research → Data → Verification → Trust Engine → "
        "Policy Gate) and returns the structured result with claims, evidence, "
        "trust score and decision."
    ),
    responses={
        422: {"description": "Validation error — missing or invalid fields."},
        500: {
            "description": "Pipeline execution error.",
            "model": ErrorResponse,
        },
    },
)
def analyze(
    request: AnalyzeRequest,
    current_user: Optional[dict] = Depends(get_user_for_analyze),
) -> AnalyzeResponse | ErrorResponse:
    """POST /api/analyze handler."""

    # 1. Generate unique task_id
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    logger.info("New analysis request  task_id=%s  query=%r", task_id, request.query[:80])

    # 2. Run pipeline
    try:
        raw_result: dict = run_pipeline(
            query=request.query,
            task_id=task_id,
            options=request.options,
        )
    except Exception as exc:
        # Pipeline raised an unexpected exception — return structured error
        error_msg = f"Pipeline execution failed: {exc}"
        logger.error("Pipeline error  task_id=%s  %s", task_id, error_msg)
        logger.debug(traceback.format_exc())

        return ErrorResponse(
            task_id=task_id,
            status="ERROR",
            query=request.query,
            errors=[error_msg],
        )

    # 3. Ensure the response has the query echoed back
    raw_result.setdefault("query", request.query)

    # 4. Map pipeline status to a structured response
    pipeline_status = raw_result.get("status", "ERROR")

    if pipeline_status == "ERROR":
        return ErrorResponse(
            task_id=raw_result.get("task_id", task_id),
            status="ERROR",
            query=raw_result.get("query", request.query),
            errors=raw_result.get("errors", [raw_result.get("error", "Unknown pipeline error")]),
        )

    # 5. Build the success response — map agreed fields
    try:
        response = AnalyzeResponse(**raw_result)
    except Exception as exc:
        # Pipeline returned an unexpected shape — wrap in error
        error_msg = f"Pipeline response validation failed: {exc}"
        logger.error("Response validation error  task_id=%s  %s", task_id, error_msg)
        return ErrorResponse(
            task_id=task_id,
            status="ERROR",
            query=request.query,
            errors=[error_msg],
        )

    return response
