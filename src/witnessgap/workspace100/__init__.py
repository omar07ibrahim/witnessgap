"""Authored corpus and evaluation machinery for Workspace-100."""

from witnessgap.workspace100.catalog import TEMPLATES, VARIANTS
from witnessgap.workspace100.generation import (
    GeneratedCompletion,
    GeneratedPair,
    Workspace100Corpus,
    authored_completion_records,
    construction_matrix,
    generate_workspace100,
)
from witnessgap.workspace100.records import (
    PROTOCOL_ID,
    SOURCE_FORMAT_ID,
    CompletionSourceRecord,
    ResolverBinding,
    Split,
    TemplateId,
    TemplateRecord,
    VariantRecord,
)
from witnessgap.workspace100.runtime import (
    WORKSPACE100_ADAPTER_ID,
    WORKSPACE100_OWNER_PROBE,
    Workspace100SourceAdapter,
    Workspace100World,
    workspace100_adapter_implementation_digest,
    workspace100_pair_worlds,
)

__all__ = [
    "PROTOCOL_ID",
    "SOURCE_FORMAT_ID",
    "TEMPLATES",
    "VARIANTS",
    "WORKSPACE100_ADAPTER_ID",
    "WORKSPACE100_OWNER_PROBE",
    "CompletionSourceRecord",
    "GeneratedCompletion",
    "GeneratedPair",
    "ResolverBinding",
    "Split",
    "TemplateId",
    "TemplateRecord",
    "VariantRecord",
    "Workspace100Corpus",
    "Workspace100SourceAdapter",
    "Workspace100World",
    "authored_completion_records",
    "construction_matrix",
    "generate_workspace100",
    "workspace100_adapter_implementation_digest",
    "workspace100_pair_worlds",
]
