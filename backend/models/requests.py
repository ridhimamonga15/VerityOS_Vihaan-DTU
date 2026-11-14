"""
Pydantic request models — Member 3.

Defines the input contract for POST /api/analyze.
Fields match the agreed blueprint schemas.
"""

from pydantic import BaseModel, Field
from typing import Optional


class AnalyzeRequest(BaseModel):
    """
    Request body for POST /api/analyze.

    Attributes:
        query:   The user's natural-language research / analysis question.
                 Must be non-empty and at most 5 000 characters.
        options: Optional dictionary for pipeline configuration
                 (e.g. {"mode": "collaborative"}).  Passed through to
                 execute_pipeline() without modification.
    """

    query: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The user's research or analysis question.",
        examples=["Prepare a short market research report about Company X."],
    )
    options: Optional[dict] = Field(
        default=None,
        description="Optional pipeline configuration (e.g. mode, parameters).",
        examples=[{"mode": "collaborative"}],
    )
