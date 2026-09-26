"""
Base agent class for SECUREFIX agents.
"""
import time
import traceback
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from app.models import AgentResult, AgentStatus, Investigation


class BaseAgent(ABC):
    name: str = "base_agent"

    async def run(self, investigation: Investigation) -> AgentResult:
        start = time.time()
        try:
            result = await self._execute(investigation)
            result.duration_ms = int((time.time() - start) * 1000)
            result.status = AgentStatus.COMPLETED
            return result
        except Exception as exc:
            duration_ms = int((time.time() - start) * 1000)
            return AgentResult(
                agent=self.name,
                status=AgentStatus.FAILED,
                duration_ms=duration_ms,
                error=str(exc),
                summary=f"Agent failed: {exc}",
            )

    @abstractmethod
    async def _execute(self, investigation: Investigation) -> AgentResult:
        """Implement agent logic here."""
        ...
