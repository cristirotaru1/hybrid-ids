"""Version 2 flow features with explicit TCP and ICMP semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ids_ml.features import FlowFeatures, calculate_flow_features
from ids_ml.flows import Flow
from ids_ml.history import is_failed_connection
from ids_ml.packets import IPProtocol

NOT_APPLICABLE = -1
ICMP_ERROR_TYPES = frozenset({3, 4, 5, 11, 12})


@dataclass(frozen=True, slots=True)
class FlowFeaturesV2(FlowFeatures):
    """Version 1 measurements plus protocol semantics required by model v2."""

    current_tcp_failed: int
    icmp_type_group: int
    icmp_code: int
    icmp_is_error: int


class FeatureV2CalculationError(ValueError):
    """Raised when a flow lacks fields required by feature schema v2."""


def calculate_flow_features_v2(flow: Flow) -> FlowFeaturesV2:
    """Calculate deterministic version 2 features for one completed flow."""
    base = calculate_flow_features(flow)
    if flow.key.protocol is IPProtocol.ICMP:
        if flow.key.icmp_type_group is None or flow.key.icmp_code is None:
            raise FeatureV2CalculationError(
                "an ICMP flow requires a type group and code"
            )
        icmp_type_group = flow.key.icmp_type_group
        icmp_code = flow.key.icmp_code
        icmp_is_error = int(icmp_type_group in ICMP_ERROR_TYPES)
    else:
        icmp_type_group = NOT_APPLICABLE
        icmp_code = NOT_APPLICABLE
        icmp_is_error = 0

    return FlowFeaturesV2(
        **asdict(base),
        current_tcp_failed=int(is_failed_connection(flow)),
        icmp_type_group=icmp_type_group,
        icmp_code=icmp_code,
        icmp_is_error=icmp_is_error,
    )
