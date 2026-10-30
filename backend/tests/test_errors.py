"""The API must return one consistent error shape and never leak internals."""

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _add_probe_routes(app: FastAPI) -> None:
    # Test-only routes that exercise the error handlers; they are not part of the real API.
    @app.get("/_probe/validated")
    def validated(limit: int) -> dict[str, int]:
        return {"limit": limit}

    @app.get("/_probe/crash")
    def crash() -> None:
        raise RuntimeError("secret internal detail: C:\\aegis\\data\\aegis.db")


def test_unknown_route_returns_structured_404(client: TestClient) -> None:
    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "not_found", "message": "Not Found"}}


def test_validation_error_is_structured_and_does_not_echo_input(app: FastAPI) -> None:
    _add_probe_routes(app)
    with TestClient(app) as client:
        response = client.get("/_probe/validated", params={"limit": "<script>alert(1)</script>"})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["loc"] == ["query", "limit"]
    assert "<script>" not in response.text


def test_unhandled_exception_hides_details(app: FastAPI) -> None:
    _add_probe_routes(app)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/_probe/crash")

    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "internal_error", "message": "An internal error occurred."}
    }
    assert "secret internal detail" not in response.text
    assert "Traceback" not in response.text
