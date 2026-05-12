from domain_config import S2PDomainConfigV2


def test_s2p_domain_config_v2_shape():
    assert S2PDomainConfigV2.domain == "s2p"
    assert len(S2PDomainConfigV2.categories) == 5
    assert len(S2PDomainConfigV2.actions) == 5
    assert len(S2PDomainConfigV2.factors) == 7


def test_s2p_domain_config_v2_categories():
    assert S2PDomainConfigV2.categories == [
        "price_variance",
        "quantity_mismatch",
        "duplicate_risk",
        "contract_gap",
        "format_compliance",
    ]
    assert S2PDomainConfigV2.actions == [
        "auto_approve",
        "hold_for_review",
        "escalate_to_buyer",
        "flag_leakage",
        "refer_to_specialist",
    ]


def test_s2p_domain_config_v2_factors_count():
    assert S2PDomainConfigV2.factors == [
        "match_status",
        "amount_variance_ratio",
        "duplicate_score",
        "supplier_exception_history",
        "payment_terms_impact",
        "commodity_index_correlation",
        "tax_regulatory_compliance",
    ]


def test_s2p_domain_config_v2_penalty_ratio():
    assert S2PDomainConfigV2.penalty_ratio == 5.0
    assert S2PDomainConfigV2.eta_confirm == 0.05
    assert S2PDomainConfigV2.eta_override == 0.01
    assert S2PDomainConfigV2.tau == 0.1


def test_s2p_domain_config_v2_tensor_size():
    assert S2PDomainConfigV2.n_categories == 5
    assert S2PDomainConfigV2.n_actions == 5
    assert S2PDomainConfigV2.n_factors == 7
    assert S2PDomainConfigV2.tensor_size() == 175
