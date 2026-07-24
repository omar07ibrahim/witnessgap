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

__all__ = [
    "PROTOCOL_ID",
    "SOURCE_FORMAT_ID",
    "TEMPLATES",
    "VARIANTS",
    "CompletionSourceRecord",
    "GeneratedCompletion",
    "GeneratedPair",
    "ResolverBinding",
    "Split",
    "TemplateId",
    "TemplateRecord",
    "VariantRecord",
    "Workspace100Corpus",
    "authored_completion_records",
    "construction_matrix",
    "generate_workspace100",
]
