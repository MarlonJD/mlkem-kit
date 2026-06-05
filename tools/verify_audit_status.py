#!/usr/bin/env python3
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "readiness/mlkem-audit-status.json"

PACKAGE_SCOPE = "ML-KEM-768 confidentiality fallback readiness"
GATE_IDS = {
    "fips203-code-map-review",
    "side-channel-review",
    "secret-lifetime-review",
    "external-crypto-review",
}
REQUIRED_TOP_LEVEL_KEYS = {
    "schemaVersion",
    "packageScope",
    "sourceCommit",
    "productionFallbackStatus",
    "externalCryptoApprovedForProduction",
    "maintainerRiskAcceptedNotCryptoApproved",
    "fallbackSelectableForExplicitRiskException",
    "gates",
}
ALLOWED_TOP_LEVEL_KEYS = REQUIRED_TOP_LEVEL_KEYS | {
    "productionFallbackRiskAcceptance",
}
GATE_KEYS = {
    "id",
    "status",
    "reviewer",
    "reviewedAt",
    "evidence",
    "blockers",
}
RISK_ACCEPTANCE_KEYS = {
    "status",
    "decisionOwner",
    "acceptedAt",
    "scope",
    "evidence",
    "constraints",
    "nonClaims",
}


def require_bool(value: object, name: str) -> bool:
    require(isinstance(value, bool), f"{name} must be a boolean")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def require_string(value: object, name: str) -> str:
    require(isinstance(value, str), f"{name} must be a string")
    return value


def require_non_empty_string_list(value: object, name: str) -> list[str]:
    require(isinstance(value, list), f"{name} must be a list")
    require(len(value) > 0, f"{name} must be non-empty")
    for index, item in enumerate(value):
        require(
            isinstance(item, str) and len(item) > 0,
            f"{name}[{index}] must be a non-empty string",
        )
    return value


def require_string_list(value: object, name: str) -> list[str]:
    require(isinstance(value, list), f"{name} must be a list")
    for index, item in enumerate(value):
        require(
            isinstance(item, str) and len(item) > 0,
            f"{name}[{index}] must be a non-empty string",
        )
    return value


def require_existing_repo_path(root: Path, evidence_path: str, gate_id: str) -> None:
    candidate = Path(evidence_path)
    require(
        not candidate.is_absolute(),
        f"{gate_id}: evidence path must be relative to repo: {evidence_path}",
    )
    resolved = (root / candidate).resolve()
    require(
        resolved.is_relative_to(root.resolve()),
        f"{gate_id}: evidence path escapes repo: {evidence_path}",
    )
    require(
        resolved.exists(),
        f"{gate_id}: evidence path does not exist: {evidence_path}",
    )


def verify_risk_acceptance(value: object, root: Path) -> None:
    require(isinstance(value, dict), "productionFallbackRiskAcceptance must be an object")
    require(
        set(value) == RISK_ACCEPTANCE_KEYS,
        "productionFallbackRiskAcceptance has unexpected fields",
    )
    require(value.get("status") == "accepted", "risk acceptance status must be accepted")
    decision_owner = require_string(
        value.get("decisionOwner"),
        "productionFallbackRiskAcceptance.decisionOwner",
    )
    accepted_at = require_string(
        value.get("acceptedAt"),
        "productionFallbackRiskAcceptance.acceptedAt",
    )
    scope = require_string(value.get("scope"), "productionFallbackRiskAcceptance.scope")
    evidence = require_non_empty_string_list(
        value.get("evidence"),
        "productionFallbackRiskAcceptance.evidence",
    )
    constraints = require_non_empty_string_list(
        value.get("constraints"),
        "productionFallbackRiskAcceptance.constraints",
    )
    non_claims = require_non_empty_string_list(
        value.get("nonClaims"),
        "productionFallbackRiskAcceptance.nonClaims",
    )

    require(len(decision_owner) > 0, "risk acceptance requires decisionOwner")
    require(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}", accepted_at) is not None,
        "risk acceptance acceptedAt must be YYYY-MM-DD",
    )
    require(len(scope) > 0, "risk acceptance requires scope")
    for evidence_path in evidence:
        require_existing_repo_path(root, evidence_path, "productionFallbackRiskAcceptance")

    joined_non_claims = " ".join(non_claims).lower()
    for required_phrase in ("fips", "constant-time", "external"):
        require(
            required_phrase in joined_non_claims,
            f"risk acceptance nonClaims must mention {required_phrase}",
        )

    joined_constraints = " ".join(constraints).lower()
    require("explicit" in joined_constraints, "risk acceptance constraints must require explicit opt-in")
    require("production" in joined_constraints, "risk acceptance constraints must mention production")


def verify(status: object, root: Path = ROOT) -> None:
    require(isinstance(status, dict), "audit status must be an object")
    require(
        REQUIRED_TOP_LEVEL_KEYS.issubset(status),
        "audit status is missing required fields",
    )
    require(set(status).issubset(ALLOWED_TOP_LEVEL_KEYS), "audit status has unexpected fields")
    require(status.get("schemaVersion") == 1, "schemaVersion must be 1")
    require(
        status.get("packageScope") == PACKAGE_SCOPE,
        f"packageScope must be {PACKAGE_SCOPE}",
    )

    source_commit = require_string(status.get("sourceCommit"), "sourceCommit")
    require(
        re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
        "sourceCommit must be 40 lowercase hex chars",
    )

    production_status = status.get("productionFallbackStatus")
    require(
        production_status in {"fail-closed", "approved"},
        "productionFallbackStatus must be fail-closed or approved",
    )

    external_crypto_approved = require_bool(
        status.get("externalCryptoApprovedForProduction"),
        "externalCryptoApprovedForProduction",
    )
    maintainer_risk_accepted = require_bool(
        status.get("maintainerRiskAcceptedNotCryptoApproved"),
        "maintainerRiskAcceptedNotCryptoApproved",
    )
    explicit_risk_exception_selectable = require_bool(
        status.get("fallbackSelectableForExplicitRiskException"),
        "fallbackSelectableForExplicitRiskException",
    )

    gates = status.get("gates")
    require(isinstance(gates, list), "gates must be a list")
    require(len(gates) == len(GATE_IDS), "gates must contain exactly the four gate ids")

    seen: set[str] = set()
    all_closed = True
    for index, gate in enumerate(gates):
        require(isinstance(gate, dict), f"gates[{index}] must be an object")
        require(set(gate) == GATE_KEYS, f"gates[{index}] has unexpected fields")

        gate_id = require_string(gate.get("id"), f"gates[{index}].id")
        require(gate_id in GATE_IDS, f"unknown gate id: {gate_id}")
        require(gate_id not in seen, f"duplicate gate id: {gate_id}")
        seen.add(gate_id)

        gate_status = gate.get("status")
        require(
            gate_status in {"open", "closed"},
            f"{gate_id}: status must be open or closed",
        )

        evidence = require_non_empty_string_list(
            gate.get("evidence"),
            f"{gate_id}.evidence",
        )
        blockers = require_string_list(gate.get("blockers"), f"{gate_id}.blockers")
        reviewer = require_string(gate.get("reviewer"), f"{gate_id}.reviewer")
        reviewed_at = require_string(gate.get("reviewedAt"), f"{gate_id}.reviewedAt")

        if gate_status == "open":
            all_closed = False
            require(len(blockers) > 0, f"{gate_id}: open gates must have blockers")
            continue

        require(len(reviewer) > 0, f"{gate_id}: closed gates require reviewer")
        require(len(reviewed_at) > 0, f"{gate_id}: closed gates require reviewedAt")
        require(len(blockers) == 0, f"{gate_id}: closed gates must not have blockers")
        for evidence_path in evidence:
            require_existing_repo_path(root, evidence_path, gate_id)

    missing = GATE_IDS - seen
    require(not missing, f"missing gate ids: {', '.join(sorted(missing))}")

    risk_acceptance = status.get("productionFallbackRiskAcceptance")
    if maintainer_risk_accepted or explicit_risk_exception_selectable:
        require(
            risk_acceptance is not None,
            "maintainer risk acceptance requires productionFallbackRiskAcceptance",
        )
        verify_risk_acceptance(risk_acceptance, root)
    elif risk_acceptance is not None:
        verify_risk_acceptance(risk_acceptance, root)

    require(
        not (external_crypto_approved and maintainer_risk_accepted),
        "maintainerRiskAcceptedNotCryptoApproved cannot be true with externalCryptoApprovedForProduction",
    )
    require(
        not (external_crypto_approved and explicit_risk_exception_selectable),
        "fallbackSelectableForExplicitRiskException cannot be true with externalCryptoApprovedForProduction",
    )
    if explicit_risk_exception_selectable:
        require(
            maintainer_risk_accepted,
            "fallbackSelectableForExplicitRiskException requires maintainerRiskAcceptedNotCryptoApproved",
        )
        require(
            production_status == "fail-closed",
            "explicit risk-exception fallback remains fail-closed, not production approved",
        )

    if production_status == "approved":
        require(all_closed, "productionFallbackStatus approved requires all gates closed")
        require(
            external_crypto_approved,
            "productionFallbackStatus approved requires externalCryptoApprovedForProduction",
        )
        require(
            not maintainer_risk_accepted,
            "productionFallbackStatus approved cannot rely on maintainer risk acceptance",
        )
    elif all_closed:
        raise SystemExit("all gates closed but productionFallbackStatus is not approved")

    if production_status == "fail-closed":
        require(
            not external_crypto_approved,
            "fail-closed productionFallbackStatus cannot claim externalCryptoApprovedForProduction",
        )


def main() -> None:
    status = json.loads(STATUS_PATH.read_text())
    verify(status)
    print("audit status ok")


if __name__ == "__main__":
    main()
