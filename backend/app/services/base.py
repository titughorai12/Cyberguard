class BaseService:
    """Base class for CyberGuard services."""

    def success(
        self,
        data=None,
        message="Operation completed successfully.",
    ):
        return {
            "success": True,
            "message": message,
            "data": data,
        }

    def error(
        self,
        message="Operation failed.",
        data=None,
    ):
        return {
            "success": False,
            "message": message,
            "data": data,
        }
