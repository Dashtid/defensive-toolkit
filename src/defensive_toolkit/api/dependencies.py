"""
FastAPI Dependencies

Common dependencies used across API routers.
"""

from defensive_toolkit.api.auth import get_current_active_user
from fastapi import Depends, HTTPException, status


async def require_admin_scope(
    current_user: str = Depends(get_current_active_user),
) -> str:
    """
    Dependency to require admin scope.

    Args:
        current_user: Current authenticated user

    Returns:
        str: Username

    Raises:
        HTTPException: If user doesn't have admin scope
    """
    # Future: Check actual user scopes from database
    # For now, only "admin" user has admin rights
    if current_user not in ["admin", "api_key_user"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


async def require_write_scope(
    current_user: str = Depends(get_current_active_user),
) -> str:
    """
    Dependency to require write scope.

    Args:
        current_user: Current authenticated user

    Returns:
        str: Username

    Raises:
        HTTPException: If user doesn't have write scope
    """
    # Future: Check actual user scopes from database
    # For now, admin and api_key_user have write access
    if current_user not in ["admin", "api_key_user"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write privileges required",
        )
    return current_user


def get_pagination_params(
    skip: int = 0,
    limit: int = 100,
) -> dict:
    """
    Pagination parameters dependency.

    Args:
        skip: Number of records to skip (default: 0)
        limit: Maximum records to return (default: 100, max: 1000)

    Returns:
        dict: Pagination parameters
    """
    # Enforce max limit
    if limit > 1000:
        limit = 1000

    return {"skip": skip, "limit": limit}
