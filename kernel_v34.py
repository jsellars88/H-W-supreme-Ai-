"""
WhiteSwan Governance Kernel v3.4 — Re-export Module

Provides ``import kernel_v34 as k34`` compatibility by re-exporting
everything from whiteswan_governance_kernel_v3_4.
"""

from whiteswan_governance_kernel_v3_4 import *  # noqa: F401,F403

# Private helpers needed by kernel_v35 — not included in wildcard import
from whiteswan_governance_kernel_v3_4 import _json_canon  # noqa: F401
