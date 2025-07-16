import uuid
from typing import Tuple, Optional
from core.config_loader import AIModuleConfig

class PayloadGenerator:
    """
    Generates payloads for various vulnerabilities.
    """
    def __init__(self, config: Optional[AIModuleConfig] = None):
        self.config = config

    def generate_xss_payload(self) -> Tuple[str, str]:
        """
        Generates a unique XSS payload with a taint ID.

        Returns:
            A tuple containing the payload and the taint ID.
        """
        taint_id = f"avs-taint-{uuid.uuid4()}"
        payload = f"<script>alert('{taint_id}')</script>"
        return payload, taint_id



