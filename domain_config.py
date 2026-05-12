"""Shared domain configuration contracts."""


class S2PDomainConfigV2:
    """Canonical Source-to-Pay invoice exception domain configuration."""

    domain = "s2p"

    categories = [
        "price_variance",
        "quantity_mismatch",
        "duplicate_risk",
        "contract_gap",
        "format_compliance",
    ]

    actions = [
        "auto_approve",
        "hold_for_review",
        "escalate_to_buyer",
        "flag_leakage",
        "refer_to_specialist",
    ]

    factors = [
        "match_status",
        "amount_variance_ratio",
        "duplicate_score",
        "supplier_exception_history",
        "payment_terms_impact",
        "commodity_index_correlation",
        "tax_regulatory_compliance",
    ]

    penalty_ratio = 5.0
    eta_confirm = 0.05
    eta_override = 0.01
    tau = 0.1

    n_categories = len(categories)
    n_actions = len(actions)
    n_factors = len(factors)

    @classmethod
    def tensor_size(cls) -> int:
        return cls.n_categories * cls.n_actions * cls.n_factors
