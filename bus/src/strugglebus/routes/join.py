"""Serve the agent join scripts named by the onboarding package.

They are public, static and identical for everyone: a new agent has no
credential yet, and it fetches them over TLS verified against the certificate
root its onboarding package carries.
"""

from __future__ import annotations

from importlib import resources

from fastapi import APIRouter, Response

JOIN_SCRIPTS = {
    "/join.sh": ("join.sh", "text/x-shellscript; charset=utf-8"),
    "/join.ps1": ("join.ps1", "text/plain; charset=utf-8"),
}


def join_script(name: str) -> bytes:
    return (
        resources.files("strugglebus").joinpath("selfhost", "agent", name).read_bytes()
    )


def add_join_routes(router: APIRouter) -> None:
    def serve(name: str, media_type: str) -> Response:
        return Response(
            content=join_script(name),
            media_type=media_type,
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": (
                    "default-src 'none'; base-uri 'none'; form-action 'none'; "
                    "frame-ancestors 'none'"
                ),
            },
        )

    @router.get("/join.sh", include_in_schema=False)
    async def join_sh() -> Response:
        return serve(*JOIN_SCRIPTS["/join.sh"])

    @router.get("/join.ps1", include_in_schema=False)
    async def join_ps1() -> Response:
        return serve(*JOIN_SCRIPTS["/join.ps1"])
