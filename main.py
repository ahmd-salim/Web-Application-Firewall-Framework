from fastapi import FastAPI, Request
from fastapi.responses import Response
import httpx

app = FastAPI()

TARGET = "http://localhost:8001"


async def _forward(path: str, request: Request) -> Response:
    url = f"{TARGET}/{path}" if path else TARGET

    body = await request.body()

    # ===== Request Inspection (WAF Stage 1) =====
    print("\n===== Incoming Request =====")
    print("Method:", request.method)
    print("Path:", request.url.path)
    print("Query Params:", dict(request.query_params))
    print("Headers:", dict(request.headers))
    print("Body:", body.decode(errors="ignore"))
    print("============================\n")

    async with httpx.AsyncClient(follow_redirects=False) as client:
        backend_response = await client.request(
            method=request.method,
            url=url,
            params=request.query_params,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            content=body,
        )

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=dict(backend_response.headers),
    )


@app.api_route("/", methods=["GET", "POST"])
async def reverse_proxy_root(request: Request) -> Response:
    return await _forward("", request)


@app.api_route("/{path:path}", methods=["GET", "POST"])
async def reverse_proxy_path(path: str, request: Request) -> Response:
    return await _forward(path, request)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
