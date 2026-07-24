"""Explicit authored catalog for the frozen Workspace-100 protocol."""

from __future__ import annotations

from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.workspace100.records import (
    PROTOCOL_ID,
    Split,
    TemplateId,
    TemplateRecord,
    VariantRecord,
)

FORBIDDEN_PARTICIPANT_TERMS = (
    "environment",
    "policy",
    "stale",
    "current",
    "good",
    "bad",
    "fault",
    "cause",
)

_VARIANT_IDS = (
    "v00",
    "v01",
    "v02",
    "v03",
    "v04",
    "v05",
    "v06",
    "v07",
    "v08",
    "v09",
)
_TEMPLATE_COUNT = 5
_VARIANT_COUNT = 50

TEMPLATES = (
    TemplateRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        split=Split.DEVELOPMENT,
        task_schema_id="workspace100_publish_draft_v1",
        goal_selector="approved_draft",
        alternate_selector="previous_draft",
        refresh_atom="refresh_draft_store",
        repair_atom="repair_draft_selection",
        epoch_probe="draft_store_epoch",
        selection_channel="draft_selection",
        resolver_channel="draft_store",
        lookup_tool="read_draft",
        action_tool="publish_draft",
        terminal_success="approved_content_present",
        terminal_failure="approved_content_missing",
    ),
    TemplateRecord(
        template_id=TemplateId.INVITE_MEMBER,
        split=Split.DEVELOPMENT,
        task_schema_id="workspace100_invite_member_v1",
        goal_selector="approved_role",
        alternate_selector="viewer_role",
        refresh_atom="refresh_role_catalog",
        repair_atom="repair_role_selection",
        epoch_probe="role_catalog_epoch",
        selection_channel="role_selection",
        resolver_channel="role_catalog",
        lookup_tool="resolve_member_role",
        action_tool="invite_workspace_member",
        terminal_success="requested_role_present",
        terminal_failure="requested_role_missing",
    ),
    TemplateRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        split=Split.VALIDATION,
        task_schema_id="workspace100_move_work_item_v1",
        goal_selector="review_lane",
        alternate_selector="triage_lane",
        refresh_atom="refresh_lane_resolver",
        repair_atom="repair_lane_selection",
        epoch_probe="lane_resolver_epoch",
        selection_channel="lane_selection",
        resolver_channel="lane_resolver",
        lookup_tool="resolve_board_lane",
        action_tool="move_board_item",
        terminal_success="requested_lane_present",
        terminal_failure="requested_lane_missing",
    ),
    TemplateRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        split=Split.TEST,
        task_schema_id="workspace100_schedule_review_v1",
        goal_selector="approved_window",
        alternate_selector="fallback_window",
        refresh_atom="refresh_calendar_snapshot",
        repair_atom="repair_review_selection",
        epoch_probe="calendar_epoch",
        selection_channel="review_selection",
        resolver_channel="calendar_snapshot",
        lookup_tool="resolve_review_window",
        action_tool="book_review_slot",
        terminal_success="requested_slot_present",
        terminal_failure="requested_slot_missing",
    ),
    TemplateRecord(
        template_id=TemplateId.GRANT_ACCESS,
        split=Split.TEST,
        task_schema_id="workspace100_grant_access_v1",
        goal_selector="approved_scope",
        alternate_selector="commenter_scope",
        refresh_atom="refresh_permission_catalog",
        repair_atom="repair_scope_selection",
        epoch_probe="permission_catalog_epoch",
        selection_channel="scope_selection",
        resolver_channel="permission_catalog",
        lookup_tool="resolve_access_scope",
        action_tool="grant_workspace_access",
        terminal_success="requested_scope_present",
        terminal_failure="requested_scope_missing",
    ),
)

VARIANTS = (
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v00",
        workspace_slug="northstar_studio",
        subject_id="draft_northstar_launch",
        subject_display="Northstar launch brief",
        owner="mina_park",
        public_task=("Publish Northstar launch brief (Edition 31) in Northstar Studio."),
        intended_concrete_id="revision_northstar_31",
        observed_concrete_id="revision_northstar_24",
        intended_display="Edition 31",
        observed_display="Edition 24",
        reference_epoch_id="draft_index_northstar_31",
        alternate_epoch_id="draft_index_northstar_24",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v01",
        workspace_slug="cedar_lab",
        subject_id="draft_cedar_research",
        subject_display="Cedar research digest",
        owner="leo_martin",
        public_task="Publish Cedar research digest (Edition 18) in Cedar Lab.",
        intended_concrete_id="revision_cedar_18",
        observed_concrete_id="revision_cedar_12",
        intended_display="Edition 18",
        observed_display="Edition 12",
        reference_epoch_id="draft_index_cedar_18",
        alternate_epoch_id="draft_index_cedar_12",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v02",
        workspace_slug="mariner_desk",
        subject_id="draft_mariner_route",
        subject_display="Mariner route summary",
        owner="sana_cho",
        public_task="Publish Mariner route summary (Edition 27) in Mariner Desk.",
        intended_concrete_id="revision_mariner_27",
        observed_concrete_id="revision_mariner_21",
        intended_display="Edition 27",
        observed_display="Edition 21",
        reference_epoch_id="draft_index_mariner_27",
        alternate_epoch_id="draft_index_mariner_21",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v03",
        workspace_slug="lumen_press",
        subject_id="draft_lumen_product",
        subject_display="Lumen product bulletin",
        owner="eli_turner",
        public_task="Publish Lumen product bulletin (Edition 42) in Lumen Press.",
        intended_concrete_id="revision_lumen_42",
        observed_concrete_id="revision_lumen_35",
        intended_display="Edition 42",
        observed_display="Edition 35",
        reference_epoch_id="draft_index_lumen_42",
        alternate_epoch_id="draft_index_lumen_35",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v04",
        workspace_slug="orion_works",
        subject_id="draft_orion_field",
        subject_display="Orion field report",
        owner="nora_bell",
        public_task="Publish Orion field report (Edition 16) in Orion Works.",
        intended_concrete_id="revision_orion_16",
        observed_concrete_id="revision_orion_09",
        intended_display="Edition 16",
        observed_display="Edition 9",
        reference_epoch_id="draft_index_orion_16",
        alternate_epoch_id="draft_index_orion_09",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v05",
        workspace_slug="harbor_notes",
        subject_id="draft_harbor_ops",
        subject_display="Harbor operations memo",
        owner="amir_shah",
        public_task="Publish Harbor operations memo (Edition 23) in Harbor Notes.",
        intended_concrete_id="revision_harbor_23",
        observed_concrete_id="revision_harbor_17",
        intended_display="Edition 23",
        observed_display="Edition 17",
        reference_epoch_id="draft_index_harbor_23",
        alternate_epoch_id="draft_index_harbor_17",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v06",
        workspace_slug="summit_ink",
        subject_id="draft_summit_market",
        subject_display="Summit market note",
        owner="ivy_nguyen",
        public_task="Publish Summit market note (Edition 38) in Summit Ink.",
        intended_concrete_id="revision_summit_38",
        observed_concrete_id="revision_summit_30",
        intended_display="Edition 38",
        observed_display="Edition 30",
        reference_epoch_id="draft_index_summit_38",
        alternate_epoch_id="draft_index_summit_30",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v07",
        workspace_slug="willow_media",
        subject_id="draft_willow_partner",
        subject_display="Willow partner update",
        owner="omar_reed",
        public_task="Publish Willow partner update (Edition 20) in Willow Media.",
        intended_concrete_id="revision_willow_20",
        observed_concrete_id="revision_willow_14",
        intended_display="Edition 20",
        observed_display="Edition 14",
        reference_epoch_id="draft_index_willow_20",
        alternate_epoch_id="draft_index_willow_14",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v08",
        workspace_slug="cobalt_house",
        subject_id="draft_cobalt_design",
        subject_display="Cobalt design brief",
        owner="zoe_kim",
        public_task="Publish Cobalt design brief (Edition 34) in Cobalt House.",
        intended_concrete_id="revision_cobalt_34",
        observed_concrete_id="revision_cobalt_28",
        intended_display="Edition 34",
        observed_display="Edition 28",
        reference_epoch_id="draft_index_cobalt_34",
        alternate_epoch_id="draft_index_cobalt_28",
    ),
    VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v09",
        workspace_slug="aurora_brief",
        subject_id="draft_aurora_program",
        subject_display="Aurora program recap",
        owner="ben_sato",
        public_task="Publish Aurora program recap (Edition 29) in Aurora Brief.",
        intended_concrete_id="revision_aurora_29",
        observed_concrete_id="revision_aurora_22",
        intended_display="Edition 29",
        observed_display="Edition 22",
        reference_epoch_id="draft_index_aurora_29",
        alternate_epoch_id="draft_index_aurora_22",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v00",
        workspace_slug="meadow_circle",
        subject_id="member_meadow_lee",
        subject_display="Jordan Lee",
        owner="anika_rao",
        public_task="Invite Jordan Lee to Meadow Circle as Editor.",
        intended_concrete_id="role_meadow_editor",
        observed_concrete_id="role_meadow_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_meadow_18",
        alternate_epoch_id="role_index_meadow_12",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v01",
        workspace_slug="quartz_team",
        subject_id="member_quartz_diaz",
        subject_display="Camila Diaz",
        owner="marcus_yu",
        public_task="Invite Camila Diaz to Quartz Team as Editor.",
        intended_concrete_id="role_quartz_editor",
        observed_concrete_id="role_quartz_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_quartz_26",
        alternate_epoch_id="role_index_quartz_19",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v02",
        workspace_slug="pine_hub",
        subject_id="member_pine_okafor",
        subject_display="Nia Okafor",
        owner="tariq_ali",
        public_task="Invite Nia Okafor to Pine Hub as Editor.",
        intended_concrete_id="role_pine_editor",
        observed_concrete_id="role_pine_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_pine_14",
        alternate_epoch_id="role_index_pine_08",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v03",
        workspace_slug="delta_collective",
        subject_id="member_delta_chen",
        subject_display="Wei Chen",
        owner="lucia_gomez",
        public_task="Invite Wei Chen to Delta Collective as Editor.",
        intended_concrete_id="role_delta_editor",
        observed_concrete_id="role_delta_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_delta_33",
        alternate_epoch_id="role_index_delta_27",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v04",
        workspace_slug="ember_group",
        subject_id="member_ember_wilson",
        subject_display="Ava Wilson",
        owner="hugo_larsen",
        public_task="Invite Ava Wilson to Ember Group as Editor.",
        intended_concrete_id="role_ember_editor",
        observed_concrete_id="role_ember_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_ember_21",
        alternate_epoch_id="role_index_ember_15",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v05",
        workspace_slug="terra_room",
        subject_id="member_terra_singh",
        subject_display="Arjun Singh",
        owner="fatima_noor",
        public_task="Invite Arjun Singh to Terra Room as Editor.",
        intended_concrete_id="role_terra_editor",
        observed_concrete_id="role_terra_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_terra_17",
        alternate_epoch_id="role_index_terra_11",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v06",
        workspace_slug="river_club",
        subject_id="member_river_brown",
        subject_display="Maya Brown",
        owner="kenji_mori",
        public_task="Invite Maya Brown to River Club as Editor.",
        intended_concrete_id="role_river_editor",
        observed_concrete_id="role_river_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_river_31",
        alternate_epoch_id="role_index_river_25",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v07",
        workspace_slug="opal_network",
        subject_id="member_opal_roche",
        subject_display="Theo Roche",
        owner="dalia_hassan",
        public_task="Invite Theo Roche to Opal Network as Editor.",
        intended_concrete_id="role_opal_editor",
        observed_concrete_id="role_opal_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_opal_24",
        alternate_epoch_id="role_index_opal_16",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v08",
        workspace_slug="maple_guild",
        subject_id="member_maple_evans",
        subject_display="Riley Evans",
        owner="pavel_ivanov",
        public_task="Invite Riley Evans to Maple Guild as Editor.",
        intended_concrete_id="role_maple_editor",
        observed_concrete_id="role_maple_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_maple_28",
        alternate_epoch_id="role_index_maple_20",
    ),
    VariantRecord(
        template_id=TemplateId.INVITE_MEMBER,
        variant_id="v09",
        workspace_slug="solstice_unit",
        subject_id="member_solstice_baker",
        subject_display="Morgan Baker",
        owner="yara_saleh",
        public_task="Invite Morgan Baker to Solstice Unit as Editor.",
        intended_concrete_id="role_solstice_editor",
        observed_concrete_id="role_solstice_viewer",
        intended_display="Editor",
        observed_display="Viewer",
        reference_epoch_id="role_index_solstice_36",
        alternate_epoch_id="role_index_solstice_29",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v00",
        workspace_slug="axiom_board",
        subject_id="item_axiom_184",
        subject_display="Search relevance audit",
        owner="clara_fischer",
        public_task="Move Search relevance audit to Review in Axiom Board.",
        intended_concrete_id="lane_axiom_review",
        observed_concrete_id="lane_axiom_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_axiom_14",
        alternate_epoch_id="lane_index_axiom_09",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v01",
        workspace_slug="birch_board",
        subject_id="item_birch_271",
        subject_display="Mobile checkout polish",
        owner="diego_costa",
        public_task="Move Mobile checkout polish to Review in Birch Board.",
        intended_concrete_id="lane_birch_review",
        observed_concrete_id="lane_birch_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_birch_22",
        alternate_epoch_id="lane_index_birch_17",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v02",
        workspace_slug="coral_board",
        subject_id="item_coral_306",
        subject_display="Billing export refinement",
        owner="hana_suzuki",
        public_task="Move Billing export refinement to Review in Coral Board.",
        intended_concrete_id="lane_coral_review",
        observed_concrete_id="lane_coral_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_coral_19",
        alternate_epoch_id="lane_index_coral_13",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v03",
        workspace_slug="drift_board",
        subject_id="item_drift_419",
        subject_display="Usage digest refresh",
        owner="samir_khan",
        public_task="Move Usage digest refresh to Review in Drift Board.",
        intended_concrete_id="lane_drift_review",
        observed_concrete_id="lane_drift_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_drift_27",
        alternate_epoch_id="lane_index_drift_21",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v04",
        workspace_slug="elm_board",
        subject_id="item_elm_522",
        subject_display="Account merge safeguards",
        owner="nadia_petrova",
        public_task="Move Account merge safeguards to Review in Elm Board.",
        intended_concrete_id="lane_elm_review",
        observed_concrete_id="lane_elm_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_elm_32",
        alternate_epoch_id="lane_index_elm_26",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v05",
        workspace_slug="fjord_board",
        subject_id="item_fjord_618",
        subject_display="Warehouse sync tuning",
        owner="joel_mensah",
        public_task="Move Warehouse sync tuning to Review in Fjord Board.",
        intended_concrete_id="lane_fjord_review",
        observed_concrete_id="lane_fjord_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_fjord_25",
        alternate_epoch_id="lane_index_fjord_18",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v06",
        workspace_slug="grove_board",
        subject_id="item_grove_703",
        subject_display="Notification routing pass",
        owner="elena_popov",
        public_task="Move Notification routing pass to Review in Grove Board.",
        intended_concrete_id="lane_grove_review",
        observed_concrete_id="lane_grove_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_grove_41",
        alternate_epoch_id="lane_index_grove_34",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v07",
        workspace_slug="helios_board",
        subject_id="item_helios_845",
        subject_display="Session timeout review",
        owner="luis_mendez",
        public_task="Move Session timeout review to Review in Helios Board.",
        intended_concrete_id="lane_helios_review",
        observed_concrete_id="lane_helios_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_helios_16",
        alternate_epoch_id="lane_index_helios_10",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v08",
        workspace_slug="islet_board",
        subject_id="item_islet_932",
        subject_display="Analytics filter cleanup",
        owner="priya_desai",
        public_task="Move Analytics filter cleanup to Review in Islet Board.",
        intended_concrete_id="lane_islet_review",
        observed_concrete_id="lane_islet_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_islet_29",
        alternate_epoch_id="lane_index_islet_23",
    ),
    VariantRecord(
        template_id=TemplateId.MOVE_WORK_ITEM,
        variant_id="v09",
        workspace_slug="juniper_board",
        subject_id="item_juniper_107",
        subject_display="Import mapping update",
        owner="antoine_dubois",
        public_task="Move Import mapping update to Review in Juniper Board.",
        intended_concrete_id="lane_juniper_review",
        observed_concrete_id="lane_juniper_triage",
        intended_display="Review",
        observed_display="Triage",
        reference_epoch_id="lane_index_juniper_38",
        alternate_epoch_id="lane_index_juniper_30",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v00",
        workspace_slug="kepler_calendar",
        subject_id="review_kepler_launch",
        subject_display="Kepler launch review",
        owner="sofia_rossi",
        public_task=(
            "Schedule Kepler launch review for 14 October 2026, 15:00 UTC in Kepler Calendar."
        ),
        intended_concrete_id="slot_kepler_20261014_1500",
        observed_concrete_id="slot_kepler_20261007_1500",
        intended_display="14 October 2026, 15:00 UTC",
        observed_display="7 October 2026, 15:00 UTC",
        reference_epoch_id="calendar_index_kepler_44",
        alternate_epoch_id="calendar_index_kepler_37",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v01",
        workspace_slug="lagoon_calendar",
        subject_id="review_lagoon_risk",
        subject_display="Lagoon risk review",
        owner="mohamed_adel",
        public_task=(
            "Schedule Lagoon risk review for 3 November 2026, 09:30 UTC in Lagoon Calendar."
        ),
        intended_concrete_id="slot_lagoon_20261103_0930",
        observed_concrete_id="slot_lagoon_20261027_0930",
        intended_display="3 November 2026, 09:30 UTC",
        observed_display="27 October 2026, 09:30 UTC",
        reference_epoch_id="calendar_index_lagoon_28",
        alternate_epoch_id="calendar_index_lagoon_21",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v02",
        workspace_slug="mesa_calendar",
        subject_id="review_mesa_architecture",
        subject_display="Mesa architecture review",
        owner="greta_weber",
        public_task=(
            "Schedule Mesa architecture review for 19 November 2026, 17:00 UTC in Mesa Calendar."
        ),
        intended_concrete_id="slot_mesa_20261119_1700",
        observed_concrete_id="slot_mesa_20261112_1700",
        intended_display="19 November 2026, 17:00 UTC",
        observed_display="12 November 2026, 17:00 UTC",
        reference_epoch_id="calendar_index_mesa_35",
        alternate_epoch_id="calendar_index_mesa_28",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v03",
        workspace_slug="nova_calendar",
        subject_id="review_nova_security",
        subject_display="Nova security review",
        owner="isaac_cohen",
        public_task=(
            "Schedule Nova security review for 2 December 2026, 13:30 UTC in Nova Calendar."
        ),
        intended_concrete_id="slot_nova_20261202_1330",
        observed_concrete_id="slot_nova_20261125_1330",
        intended_display="2 December 2026, 13:30 UTC",
        observed_display="25 November 2026, 13:30 UTC",
        reference_epoch_id="calendar_index_nova_51",
        alternate_epoch_id="calendar_index_nova_44",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v04",
        workspace_slug="oasis_calendar",
        subject_id="review_oasis_release",
        subject_display="Oasis release review",
        owner="lina_nasir",
        public_task=(
            "Schedule Oasis release review for 16 December 2026, 11:00 UTC in Oasis Calendar."
        ),
        intended_concrete_id="slot_oasis_20261216_1100",
        observed_concrete_id="slot_oasis_20261209_1100",
        intended_display="16 December 2026, 11:00 UTC",
        observed_display="9 December 2026, 11:00 UTC",
        reference_epoch_id="calendar_index_oasis_39",
        alternate_epoch_id="calendar_index_oasis_32",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v05",
        workspace_slug="prairie_calendar",
        subject_id="review_prairie_data",
        subject_display="Prairie data review",
        owner="mateo_silva",
        public_task=(
            "Schedule Prairie data review for 12 January 2027, 16:30 UTC in Prairie Calendar."
        ),
        intended_concrete_id="slot_prairie_20270112_1630",
        observed_concrete_id="slot_prairie_20270105_1630",
        intended_display="12 January 2027, 16:30 UTC",
        observed_display="5 January 2027, 16:30 UTC",
        reference_epoch_id="calendar_index_prairie_47",
        alternate_epoch_id="calendar_index_prairie_40",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v06",
        workspace_slug="quill_calendar",
        subject_id="review_quill_research",
        subject_display="Quill research review",
        owner="emily_clark",
        public_task=(
            "Schedule Quill research review for 28 January 2027, 10:00 UTC in Quill Calendar."
        ),
        intended_concrete_id="slot_quill_20270128_1000",
        observed_concrete_id="slot_quill_20270121_1000",
        intended_display="28 January 2027, 10:00 UTC",
        observed_display="21 January 2027, 10:00 UTC",
        reference_epoch_id="calendar_index_quill_31",
        alternate_epoch_id="calendar_index_quill_24",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v07",
        workspace_slug="ridge_calendar",
        subject_id="review_ridge_partner",
        subject_display="Ridge partner review",
        owner="victor_chen",
        public_task=(
            "Schedule Ridge partner review for 9 February 2027, 14:30 UTC in Ridge Calendar."
        ),
        intended_concrete_id="slot_ridge_20270209_1430",
        observed_concrete_id="slot_ridge_20270202_1430",
        intended_display="9 February 2027, 14:30 UTC",
        observed_display="2 February 2027, 14:30 UTC",
        reference_epoch_id="calendar_index_ridge_58",
        alternate_epoch_id="calendar_index_ridge_51",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v08",
        workspace_slug="sierra_calendar",
        subject_id="review_sierra_quality",
        subject_display="Sierra quality review",
        owner="aisha_bello",
        public_task=(
            "Schedule Sierra quality review for 23 February 2027, 08:30 UTC in Sierra Calendar."
        ),
        intended_concrete_id="slot_sierra_20270223_0830",
        observed_concrete_id="slot_sierra_20270216_0830",
        intended_display="23 February 2027, 08:30 UTC",
        observed_display="16 February 2027, 08:30 UTC",
        reference_epoch_id="calendar_index_sierra_42",
        alternate_epoch_id="calendar_index_sierra_35",
    ),
    VariantRecord(
        template_id=TemplateId.SCHEDULE_REVIEW,
        variant_id="v09",
        workspace_slug="tundra_calendar",
        subject_id="review_tundra_capacity",
        subject_display="Tundra capacity review",
        owner="george_hill",
        public_task=(
            "Schedule Tundra capacity review for 11 March 2027, 12:00 UTC in Tundra Calendar."
        ),
        intended_concrete_id="slot_tundra_20270311_1200",
        observed_concrete_id="slot_tundra_20270304_1200",
        intended_display="11 March 2027, 12:00 UTC",
        observed_display="4 March 2027, 12:00 UTC",
        reference_epoch_id="calendar_index_tundra_49",
        alternate_epoch_id="calendar_index_tundra_42",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v00",
        workspace_slug="umbra_vault",
        subject_id="principal_umbra_ali",
        subject_display="Samira Ali",
        owner="ronan_murphy",
        public_task="Grant Samira Ali Contributor access in Umbra Vault.",
        intended_concrete_id="scope_umbra_contributor",
        observed_concrete_id="scope_umbra_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_umbra_13",
        alternate_epoch_id="permission_index_umbra_08",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v01",
        workspace_slug="violet_vault",
        subject_id="principal_violet_kelly",
        subject_display="Robin Kelly",
        owner="salma_amin",
        public_task="Grant Robin Kelly Contributor access in Violet Vault.",
        intended_concrete_id="scope_violet_contributor",
        observed_concrete_id="scope_violet_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_violet_24",
        alternate_epoch_id="permission_index_violet_19",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v02",
        workspace_slug="wave_vault",
        subject_id="principal_wave_tan",
        subject_display="Jules Tan",
        owner="andrei_marin",
        public_task="Grant Jules Tan Contributor access in Wave Vault.",
        intended_concrete_id="scope_wave_contributor",
        observed_concrete_id="scope_wave_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_wave_17",
        alternate_epoch_id="permission_index_wave_12",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v03",
        workspace_slug="xenon_vault",
        subject_id="principal_xenon_ford",
        subject_display="Casey Ford",
        owner="maia_santos",
        public_task="Grant Casey Ford Contributor access in Xenon Vault.",
        intended_concrete_id="scope_xenon_contributor",
        observed_concrete_id="scope_xenon_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_xenon_29",
        alternate_epoch_id="permission_index_xenon_23",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v04",
        workspace_slug="yarrow_vault",
        subject_id="principal_yarrow_wood",
        subject_display="Taylor Wood",
        owner="ibrahim_musa",
        public_task="Grant Taylor Wood Contributor access in Yarrow Vault.",
        intended_concrete_id="scope_yarrow_contributor",
        observed_concrete_id="scope_yarrow_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_yarrow_36",
        alternate_epoch_id="permission_index_yarrow_30",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v05",
        workspace_slug="zenith_vault",
        subject_id="principal_zenith_moore",
        subject_display="Drew Moore",
        owner="helena_kovac",
        public_task="Grant Drew Moore Contributor access in Zenith Vault.",
        intended_concrete_id="scope_zenith_contributor",
        observed_concrete_id="scope_zenith_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_zenith_42",
        alternate_epoch_id="permission_index_zenith_35",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v06",
        workspace_slug="acorn_vault",
        subject_id="principal_acorn_hughes",
        subject_display="Quinn Hughes",
        owner="rafael_ortiz",
        public_task="Grant Quinn Hughes Contributor access in Acorn Vault.",
        intended_concrete_id="scope_acorn_contributor",
        observed_concrete_id="scope_acorn_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_acorn_20",
        alternate_epoch_id="permission_index_acorn_14",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v07",
        workspace_slug="breeze_vault",
        subject_id="principal_breeze_lam",
        subject_display="Alex Lam",
        owner="marta_nowak",
        public_task="Grant Alex Lam Contributor access in Breeze Vault.",
        intended_concrete_id="scope_breeze_contributor",
        observed_concrete_id="scope_breeze_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_breeze_31",
        alternate_epoch_id="permission_index_breeze_25",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v08",
        workspace_slug="canyon_vault",
        subject_id="principal_canyon_price",
        subject_display="Jamie Price",
        owner="osman_diallo",
        public_task="Grant Jamie Price Contributor access in Canyon Vault.",
        intended_concrete_id="scope_canyon_contributor",
        observed_concrete_id="scope_canyon_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_canyon_27",
        alternate_epoch_id="permission_index_canyon_21",
    ),
    VariantRecord(
        template_id=TemplateId.GRANT_ACCESS,
        variant_id="v09",
        workspace_slug="dune_vault",
        subject_id="principal_dune_walker",
        subject_display="Avery Walker",
        owner="bianca_romano",
        public_task="Grant Avery Walker Contributor access in Dune Vault.",
        intended_concrete_id="scope_dune_contributor",
        observed_concrete_id="scope_dune_commenter",
        intended_display="Contributor",
        observed_display="Commenter",
        reference_epoch_id="permission_index_dune_34",
        alternate_epoch_id="permission_index_dune_28",
    ),
)

_EXPECTED_SPLITS = {
    TemplateId.PUBLISH_DRAFT: Split.DEVELOPMENT,
    TemplateId.INVITE_MEMBER: Split.DEVELOPMENT,
    TemplateId.MOVE_WORK_ITEM: Split.VALIDATION,
    TemplateId.SCHEDULE_REVIEW: Split.TEST,
    TemplateId.GRANT_ACCESS: Split.TEST,
}

_PUBLIC_TASK_PREFIXES = {
    TemplateId.PUBLISH_DRAFT: "Publish ",
    TemplateId.INVITE_MEMBER: "Invite ",
    TemplateId.MOVE_WORK_ITEM: "Move ",
    TemplateId.SCHEDULE_REVIEW: "Schedule ",
    TemplateId.GRANT_ACCESS: "Grant ",
}

_FIXED_DISPLAYS = {
    TemplateId.INVITE_MEMBER: ("Editor", "Viewer"),
    TemplateId.MOVE_WORK_ITEM: ("Review", "Triage"),
    TemplateId.GRANT_ACCESS: ("Contributor", "Commenter"),
}


def participant_facing_leaks(value: object) -> tuple[str, ...]:
    """Return deterministic paths and terms found in a participant-visible tree."""

    findings: list[str] = []
    _scan_participant_value(value, path="$", findings=findings)
    return tuple(findings)


def validate_authored_catalog(
    templates: tuple[TemplateRecord, ...] = TEMPLATES,
    variants: tuple[VariantRecord, ...] = VARIANTS,
) -> None:
    """Enforce all frozen catalog invariants before generation can begin."""

    _validate_catalog_container_shapes(templates, variants)

    expected_template_ids = (
        TemplateId.PUBLISH_DRAFT,
        TemplateId.INVITE_MEMBER,
        TemplateId.MOVE_WORK_ITEM,
        TemplateId.SCHEDULE_REVIEW,
        TemplateId.GRANT_ACCESS,
    )
    if tuple(template.template_id for template in templates) != expected_template_ids:
        raise ValueError("authored templates are absent, duplicated, or out of protocol order")

    for template in templates:
        template.validate()
        if template.split is not _EXPECTED_SPLITS[template.template_id]:
            raise ValueError(f"{template.template_id.value} has the wrong grouped split")

    cursor = 0
    for template_id in expected_template_ids:
        block = variants[cursor : cursor + 10]
        if tuple(variant.template_id for variant in block) != (template_id,) * 10:
            raise ValueError(f"{template_id.value} variants are absent or out of protocol order")
        if tuple(variant.variant_id for variant in block) != _VARIANT_IDS:
            raise ValueError(f"{template_id.value} must define v00 through v09 exactly once")
        cursor += 10

    for variant in variants:
        variant.validate()
        _validate_variant_display_contract(variant)

    _require_catalog_identifiers_unique(variants)

    participant_payload: dict[str, JsonValue] = {
        "templates": tuple(template.to_payload() for template in templates),
        "variants": tuple(variant.to_payload() for variant in variants),
    }
    leaks = participant_facing_leaks(participant_payload)
    if leaks:
        raise ValueError(f"participant-facing catalog leaks reserved terms: {leaks!r}")


def _validate_catalog_container_shapes(
    templates: object,
    variants: object,
) -> None:
    if type(templates) is not tuple:
        raise TypeError("authored templates must be an exact tuple")
    if type(variants) is not tuple:
        raise TypeError("authored variants must be an exact tuple")
    if len(templates) != _TEMPLATE_COUNT:
        raise ValueError("authored catalog must contain exactly five templates")
    if len(variants) != _VARIANT_COUNT:
        raise ValueError("authored catalog must contain exactly fifty variants")
    if any(type(template) is not TemplateRecord for template in templates):
        raise TypeError("authored templates must contain exact TemplateRecord values")
    if any(type(variant) is not VariantRecord for variant in variants):
        raise TypeError("authored variants must contain exact VariantRecord values")


def _require_catalog_identifiers_unique(
    variants: tuple[VariantRecord, ...],
) -> None:
    _require_globally_unique(
        "workspace slugs",
        tuple(variant.workspace_slug for variant in variants),
    )
    _require_globally_unique(
        "subject IDs",
        tuple(variant.subject_id for variant in variants),
    )
    _require_globally_unique(
        "concrete IDs",
        tuple(
            concrete_id
            for variant in variants
            for concrete_id in (
                variant.intended_concrete_id,
                variant.observed_concrete_id,
            )
        ),
    )
    _require_globally_unique(
        "epoch IDs",
        tuple(
            epoch_id
            for variant in variants
            for epoch_id in (
                variant.reference_epoch_id,
                variant.alternate_epoch_id,
            )
        ),
    )


def template_catalog_digest(
    templates: tuple[TemplateRecord, ...] = TEMPLATES,
) -> str:
    """Commit to the ordered authored template catalog."""

    _validate_record_tuple(templates, record_type=TemplateRecord, label="templates")
    return canonical_digest(
        "witnessgap.workspace100-template-catalog.v1",
        {
            "format": "witnessgap.workspace100-template-catalog.v1",
            "protocol_id": PROTOCOL_ID,
            "templates": tuple(template.to_payload() for template in templates),
        },
    )


def variant_catalog_digest(
    variants: tuple[VariantRecord, ...] = VARIANTS,
) -> str:
    """Commit to the ordered authored variant catalog."""

    _validate_record_tuple(variants, record_type=VariantRecord, label="variants")
    return canonical_digest(
        "witnessgap.workspace100-variant-catalog.v1",
        {
            "format": "witnessgap.workspace100-variant-catalog.v1",
            "protocol_id": PROTOCOL_ID,
            "variants": tuple(variant.to_payload() for variant in variants),
        },
    )


def _validate_record_tuple(
    records: object,
    *,
    record_type: type[TemplateRecord | VariantRecord],
    label: str,
) -> None:
    if type(records) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    typed_records = cast(tuple[TemplateRecord | VariantRecord, ...], records)
    if any(type(record) is not record_type for record in typed_records):
        raise TypeError(f"{label} contain an unexpected record type")
    for record in typed_records:
        record.validate()


def _validate_variant_display_contract(variant: VariantRecord) -> None:
    prefix = _PUBLIC_TASK_PREFIXES[variant.template_id]
    workspace_display = variant.workspace_slug.replace("_", " ").title()
    if not variant.public_task.startswith(prefix):
        raise ValueError(
            f"{variant.template_id.value}/{variant.variant_id} has the wrong task verb"
        )
    for required in (
        variant.subject_display,
        variant.intended_display,
        workspace_display,
    ):
        if required not in variant.public_task:
            raise ValueError(
                f"{variant.template_id.value}/{variant.variant_id} task omits {required!r}"
            )
    if variant.observed_display in variant.public_task:
        raise ValueError(
            f"{variant.template_id.value}/{variant.variant_id} task reveals its observed result"
        )
    fixed = _FIXED_DISPLAYS.get(variant.template_id)
    if (
        fixed is not None
        and (
            variant.intended_display,
            variant.observed_display,
        )
        != fixed
    ):
        raise ValueError(
            f"{variant.template_id.value}/{variant.variant_id} has inconsistent displays"
        )


def _require_globally_unique(label: str, values: tuple[str, ...]) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"authored {label} must be globally unique")


def _scan_participant_value(
    value: object,
    *,
    path: str,
    findings: list[str],
) -> None:
    if type(value) is str:
        folded = value.casefold()
        findings.extend(f"{path}:{term}" for term in FORBIDDEN_PARTICIPANT_TERMS if term in folded)
        return
    if value is None or type(value) in {int, bool}:
        return
    if type(value) is dict:
        mapping = cast(dict[object, object], value)
        if any(type(key) is not str for key in mapping):
            raise TypeError("participant-facing object keys must be exact strings")
        typed_mapping = cast(dict[str, object], mapping)
        for key in sorted(typed_mapping):
            _scan_participant_value(key, path=f"{path}.<key>", findings=findings)
            _scan_participant_value(
                typed_mapping[key],
                path=f"{path}.{key}",
                findings=findings,
            )
        return
    if type(value) in {list, tuple}:
        sequence = cast(list[object] | tuple[object, ...], value)
        for index, item in enumerate(sequence):
            _scan_participant_value(item, path=f"{path}[{index}]", findings=findings)
        return
    raise TypeError(f"unsupported participant-facing value at {path}: {type(value).__name__}")


validate_authored_catalog()

TEMPLATE_CATALOG_DIGEST = template_catalog_digest()
VARIANT_CATALOG_DIGEST = variant_catalog_digest()
