#!/usr/bin/env python3
"""
Defensive Toolkit CLI Entry Point

Run with: python -m defensive_toolkit
Or after installation: defensive-toolkit

For production deployment, see docs/API.md
"""


def main():
    """Main entry point for the defensive toolkit API server."""
    import uvicorn

    from defensive_toolkit.api.config import get_settings

    settings = get_settings()

    print("=" * 70)
    print("Defensive Toolkit REST API")
    print("=" * 70)
    print(f"Version: {settings.app_version}")
    print(f"Starting server at: http://{settings.api_host}:{settings.api_port}")
    print(f"Swagger UI: http://localhost:{settings.api_port}/docs")
    print(f"ReDoc: http://localhost:{settings.api_port}/redoc")
    print("=" * 70)
    print("\n[!] Default Credentials:")
    print("    Username: admin | Password: changeme123")
    print("    Username: analyst | Password: analyst123")
    print("\n[!] IMPORTANT: Change default passwords in production!")
    print("=" * 70)

    uvicorn.run(
        "defensive_toolkit.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
