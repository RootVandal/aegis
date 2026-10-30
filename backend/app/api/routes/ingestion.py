from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.db.session import get_db
from app.ingestion.parser import (
    BodyError,
    InputFormat,
    ParsedRecord,
    decode_body,
    parse_json,
    parse_jsonl,
)
from app.ingestion.service import IngestionResult, ingest_records
from app.models import IngestionBatch
from app.models.enums import DataOrigin
from app.sample_data import DATASETS
from app.schemas.events import (
    DatasetOut,
    IngestionBatchOut,
    IngestionResponse,
    RecordRejectionOut,
)

router = APIRouter(tags=["ingestion"])

CONTENT_TYPES = {
    "application/x-ndjson": InputFormat.JSONL,
    "application/jsonl": InputFormat.JSONL,
    "application/json": InputFormat.JSON,
}


async def _read_limited_body(request: Request, limit: int) -> bytes:
    """Read the body but stop as soon as it exceeds ``limit`` bytes.

    Content-Length is checked first as a cheap early exit, but it is not
    trusted: the stream itself is counted, so a client that lies about the
    length (or uses chunked encoding) still cannot push more than the limit
    into memory.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise _too_large(limit)

    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > limit:
            raise _too_large(limit)
    return bytes(received)


def _too_large(limit: int) -> AppError:
    return AppError(413, "payload_too_large", f"Request body exceeds the {limit}-byte limit.")


@router.post(
    "/ingestion/batches",
    response_model=IngestionResponse,
    status_code=201,
    summary="Ingest events (JSONL or JSON)",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/x-ndjson": {"schema": {"type": "string"}},
                "application/json": {"schema": {"type": "array", "items": {"type": "object"}}},
            },
        }
    },
)
async def create_batch(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    source_name: Annotated[str, Query(min_length=1, max_length=255)] = "api-upload",
    data_origin: DataOrigin = DataOrigin.IMPORTED,
) -> IngestionResponse:
    """Send events as the raw request body.

    * ``Content-Type: application/x-ndjson`` (or ``application/jsonl``): one
      JSON object per line.
    * ``Content-Type: application/json``: one object or an array of objects.

    Valid records are stored; invalid ones are reported with their position.
    Re-sending the same events is safe: they are counted as duplicates.
    See docs/EVENT_FORMAT.md for the field reference.
    """
    settings: Settings = request.app.state.settings
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    input_format = CONTENT_TYPES.get(media_type)
    if input_format is None:
        raise AppError(
            415,
            "unsupported_media_type",
            "Use Content-Type application/x-ndjson (JSONL) or application/json.",
        )

    body = await _read_limited_body(request, settings.max_ingest_bytes)
    try:
        text = decode_body(body)
        if input_format is InputFormat.JSONL:
            parsed = parse_jsonl(text, settings.max_record_bytes)
        else:
            parsed = parse_json(text, settings.max_record_bytes)
    except BodyError as exc:
        raise AppError(400, "invalid_body", str(exc)) from None

    result = await run_in_threadpool(
        _ingest, db, parsed, settings, source_name, input_format, data_origin
    )
    return _response(result)


def _ingest(
    db: Session,
    parsed: list[ParsedRecord],
    settings: Settings,
    source_name: str,
    input_format: InputFormat,
    data_origin: DataOrigin,
) -> IngestionResult:
    if not parsed:
        raise AppError(400, "empty_body", "The request contained no events.")
    if len(parsed) > settings.max_ingest_records:
        raise AppError(
            413,
            "too_many_records",
            f"{len(parsed)} records received; the limit is {settings.max_ingest_records}.",
        )
    return ingest_records(
        db, parsed, source_name=source_name, input_format=input_format, data_origin=data_origin
    )


@router.get(
    "/ingestion/batches",
    response_model=list[IngestionBatchOut],
    summary="Recent ingestion batches",
)
def list_batches(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[IngestionBatchOut]:
    batches = db.scalars(select(IngestionBatch).order_by(IngestionBatch.id.desc()).limit(limit))
    return [IngestionBatchOut.model_validate(batch) for batch in batches]


@router.get("/datasets", response_model=list[DatasetOut], summary="Bundled sample datasets")
def list_datasets() -> list[DatasetOut]:
    return [
        DatasetOut(
            id=dataset.id,
            name=dataset.name,
            description=dataset.description,
            data_origin=DataOrigin.SYNTHETIC,
            event_count=len(dataset.generate()),
        )
        for dataset in DATASETS.values()
    ]


@router.post(
    "/datasets/{dataset_id}/load",
    response_model=IngestionResponse,
    status_code=201,
    summary="Load a bundled synthetic dataset",
)
def load_dataset(dataset_id: str, db: Annotated[Session, Depends(get_db)]) -> IngestionResponse:
    """Runs the dataset through the same normalization and storage path as an
    upload, labelled ``synthetic``. Loading it again only adds duplicates."""
    dataset = DATASETS.get(dataset_id)
    if dataset is None:
        raise AppError(404, "dataset_not_found", f"No dataset named {dataset_id!r}.")
    parsed = [
        ParsedRecord(position, record=record)
        for position, record in enumerate(dataset.generate(), start=1)
    ]
    result = ingest_records(
        db,
        parsed,
        source_name=f"sample:{dataset.id}",
        input_format=InputFormat.JSON,
        data_origin=DataOrigin.SYNTHETIC,
    )
    return _response(result)


def _response(result: IngestionResult) -> IngestionResponse:
    return IngestionResponse(
        batch=IngestionBatchOut.model_validate(result.batch),
        rejections=[
            RecordRejectionOut(position=r.position, message=r.message) for r in result.rejections
        ],
    )
