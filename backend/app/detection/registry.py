"""The set of detection rules AEGIS ships with."""

from typing import Any

from app.detection.rule import Rule
from app.detection.rules.authentication import AuthenticationAcrossAccounts, MultipleFailedLogins
from app.detection.rules.defense import SecurityConfigurationChanges
from app.detection.rules.network import SuspiciousOutboundConnections
from app.detection.rules.persistence import PersistenceMechanismChanges
from app.detection.rules.powershell import SuspiciousPowerShell
from app.detection.rules.privilege import PrivilegeEscalationIndicators
from app.detection.rules.process import SuspiciousProcessRelationships

RULES: tuple[Rule[Any], ...] = (
    MultipleFailedLogins(),
    SuspiciousPowerShell(),
    PrivilegeEscalationIndicators(),
    SuspiciousProcessRelationships(),
    PersistenceMechanismChanges(),
    SuspiciousOutboundConnections(),
    AuthenticationAcrossAccounts(),
    SecurityConfigurationChanges(),
)

RULES_BY_ID: dict[str, Rule[Any]] = {rule.id: rule for rule in RULES}
