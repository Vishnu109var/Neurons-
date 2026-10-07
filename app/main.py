"""FastAPI service exposing the unified scan endpoint for Ruchit's backend.

Run:  uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import base64
import binascii
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from .models import PipelineResult
from .nlp import load_analyzer
from .pipeline import MAX_ATTACHMENTS, Pipeline
from .scanner import MAX_ATTACHMENT_BYTES


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pipeline = Pipeline(load_analyzer())
    yield
    app.state.pipeline.close()


app = FastAPI(title="Attachment Risk Sandbox & ML Pipeline", version="1.0.0", lifespan=lifespan)


class JsonAttachment(BaseModel):
    file_name: str
    content_base64: str


class JsonScanRequest(BaseModel):
    subject: str = ""
    body: str = ""
    attachments: list[JsonAttachment] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/scan", response_model=PipelineResult)
async def scan_multipart(
    subject: str = Form(""),
    body: str = Form(""),
    files: Annotated[list[UploadFile] | None, File()] = None,
) -> PipelineResult:
    """Email body plus raw attachments as multipart/form-data."""
    attachments: list[tuple[str, bytes]] = []
    for upload in (files or [])[:MAX_ATTACHMENTS]:
        data = await upload.read(MAX_ATTACHMENT_BYTES + 1)   # cap memory use per file
        attachments.append((upload.filename or "unnamed", data))
    return await app.state.pipeline.run(subject, body, attachments)


@app.post("/v1/scan/json", response_model=PipelineResult)
async def scan_json(req: JsonScanRequest) -> PipelineResult:
    """Same thing for callers that already hold attachments as base64 strings."""
    attachments: list[tuple[str, bytes]] = []
    for item in req.attachments:
        try:
            attachments.append((item.file_name, base64.b64decode(item.content_base64, validate=True)))
        except (binascii.Error, ValueError):
            raise HTTPException(422, f"Attachment '{item.file_name}' is not valid base64")
    return await app.state.pipeline.run(req.subject, req.body, attachments)
