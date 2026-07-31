"""Tests for sharedkernel.permissions.PermissionService."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from django.test import SimpleTestCase

from sharedkernel.permissions import (
    ROLE_FLAG_NAMES,
    PermissionService,
    RuleProfile,
)
from tests.common.permission_matrix_helpers import (
    build_clarify_object,
    build_clarify_subject_users,
    build_file_inline_object,
    matrix_user,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / 'fixtures' / 'permission_matrix_baseline.json'
FORBIDDEN_PROJECT_APPS = frozenset({
    'analytics',
    'chat',
    'common',
    'crm',
    'help',
    'massmail',
    'quality',
    'settings',
    'tasks',
    'voip',
})
PERMISSIONS_PATH = Path(__file__).resolve().parents[2] / 'sharedkernel' / 'permissions.py'


def _load_baseline() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


class PermissionServiceBaselineParityTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.baseline = _load_baseline()

    def test_crm_profile_matches_clarify_permission_baseline(self):
        mismatches = []
        for row in self.baseline['clarify_permission']:
            actor, owner, co_owner = build_clarify_subject_users(row)
            obj = build_clarify_object(
                membership=row['membership'],
                department_match=row['department_match'],
                owner=owner,
                co_owner=co_owner,
            )
            result = PermissionService.can_change(actor, obj, RuleProfile.CRM)
            if result != row['expected']:
                mismatches.append(row['id'])
        self.assertEqual(mismatches, [])

    def test_attached_file_profile_matches_file_inline_baseline(self):
        mismatches = []
        for row in self.baseline['file_inline_clarify_permission']:
            counter = int(row['id'].split('-')[1])
            actor = matrix_user(**row['roles'], username=f'fi-{counter}', pk=7000 + counter)
            obj = build_file_inline_object(row, actor)
            result = PermissionService.can_change(actor, obj, RuleProfile.ATTACHED_FILE)
            if result != row['expected']:
                mismatches.append(row['id'])
        self.assertEqual(mismatches, [])

    def test_can_delete_matches_can_change_for_both_profiles(self):
        row = self.baseline['clarify_permission'][0]
        actor, owner, co_owner = build_clarify_subject_users(row)
        obj = build_clarify_object(
            membership=row['membership'],
            department_match=row['department_match'],
            owner=owner,
            co_owner=co_owner,
        )
        self.assertEqual(
            PermissionService.can_delete(actor, obj, RuleProfile.CRM),
            PermissionService.can_change(actor, obj, RuleProfile.CRM),
        )

        file_row = self.baseline['file_inline_clarify_permission'][0]
        file_actor = matrix_user(**file_row['roles'], username='fi-delete', pk=8001)
        file_obj = build_file_inline_object(file_row, file_actor)
        self.assertEqual(
            PermissionService.can_delete(file_actor, file_obj, RuleProfile.ATTACHED_FILE),
            PermissionService.can_change(file_actor, file_obj, RuleProfile.ATTACHED_FILE),
        )


class PermissionServiceRuleTests(SimpleTestCase):
    def test_crm_elevated_role_allows_chief(self):
        actor = matrix_user(is_chief=True)
        obj = SimpleNamespace(owner=matrix_user(pk=2000), department_id=99)
        self.assertTrue(PermissionService.can_change(actor, obj, RuleProfile.CRM))

    def test_crm_operator_requires_department_match(self):
        actor = matrix_user(is_operator=True, department_id=10)
        matching = SimpleNamespace(owner=matrix_user(pk=2000), department_id=10)
        other = SimpleNamespace(owner=matrix_user(pk=2000), department_id=20)
        self.assertTrue(PermissionService.can_change(actor, matching, RuleProfile.CRM))
        self.assertFalse(PermissionService.can_change(actor, other, RuleProfile.CRM))

    def test_attached_file_owner_reviewed_stage_denies(self):
        actor = matrix_user()
        obj = SimpleNamespace(owner=actor, stage='rev', REVIEWED='rev')
        self.assertFalse(PermissionService.can_change(actor, obj, RuleProfile.ATTACHED_FILE))

    def test_attached_file_no_owner_attribute_allows(self):
        actor = matrix_user()
        obj = SimpleNamespace(name='no-owner-field')
        self.assertTrue(PermissionService.can_change(actor, obj, RuleProfile.ATTACHED_FILE))

    def test_attached_file_co_owner_grant(self):
        owner = matrix_user(pk=2000)
        actor = matrix_user(pk=2001)
        obj = SimpleNamespace(owner=owner, co_owner=actor, department=True, department_id=10)
        self.assertTrue(PermissionService.can_change(actor, obj, RuleProfile.ATTACHED_FILE))


class PermissionServiceDenyByDefaultTests(SimpleTestCase):
    def test_crm_unknown_role_without_owner_grant_denies(self):
        actor = matrix_user(is_manager=True, is_accountant=True, is_department_head=True)
        obj = SimpleNamespace(
            owner=matrix_user(pk=9999),
            co_owner=matrix_user(pk=9998),
            department_id=10,
        )
        self.assertFalse(PermissionService.can_change(actor, obj, RuleProfile.CRM))

    def test_crm_unowned_object_without_matching_rule_denies(self):
        actor = matrix_user()
        obj = SimpleNamespace(department_id=10)
        self.assertFalse(PermissionService.can_change(actor, obj, RuleProfile.CRM))

    def test_attached_file_unknown_actor_denies(self):
        owner = matrix_user(pk=2000)
        actor = matrix_user(pk=2001)
        obj = SimpleNamespace(owner=owner, department=True, department_id=10)
        self.assertFalse(PermissionService.can_change(actor, obj, RuleProfile.ATTACHED_FILE))

    def test_attached_file_predicate_exception_does_not_fail_open(self):
        owner = matrix_user(pk=2000)
        actor = matrix_user(pk=2001)
        responsible = MagicMock()
        responsible.count.side_effect = RuntimeError('boom')
        obj = SimpleNamespace(
            owner=owner,
            department=True,
            department_id=10,
            responsible=responsible,
        )
        self.assertFalse(PermissionService.can_change(actor, obj, RuleProfile.ATTACHED_FILE))


class PermissionServiceLoggingTests(SimpleTestCase):
    def test_deny_emits_structured_log_without_secrets(self):
        actor = matrix_user(pk=42, is_manager=True)
        obj = SimpleNamespace(
            pk=99,
            owner=matrix_user(pk=100, username='owner@example.com'),
            department_id=10,
        )
        secret = 'super-secret-token-value'
        obj.note = secret

        with self.assertLogs('sharedkernel.permissions', level='INFO') as captured:
            allowed = PermissionService.can_change(actor, obj, RuleProfile.CRM)

        self.assertFalse(allowed)
        log_output = '\n'.join(captured.output)
        self.assertIn('Permission denied', log_output)
        self.assertIn('deny_default', log_output)
        self.assertIn('actor_id=42', log_output)
        self.assertIn('object_id=99', log_output)
        self.assertNotIn(secret, log_output)

    def test_attached_file_owner_reviewed_logs_named_rule(self):
        actor = matrix_user(pk=7)
        obj = SimpleNamespace(pk=8, owner=actor, stage='rev', REVIEWED='rev')

        with self.assertLogs('sharedkernel.permissions', level='INFO') as captured:
            allowed = PermissionService.can_change(actor, obj, RuleProfile.ATTACHED_FILE)

        self.assertFalse(allowed)
        self.assertTrue(any('owner_reviewed_stage' in entry for entry in captured.output))


class PermissionServiceIsolationTests(SimpleTestCase):
    def test_decision_path_uses_stub_objects_without_request(self):
        actor = SimpleNamespace(
            pk=1,
            department_id=10,
            is_superuser=False,
            is_chief=False,
            is_superoperator=False,
            is_operator=True,
            is_manager=False,
            is_accountant=False,
            is_task_operator=False,
            is_department_head=False,
        )
        obj = SimpleNamespace(pk=2, owner=SimpleNamespace(pk=3), department_id=10)
        self.assertTrue(PermissionService.can_change(actor, obj, RuleProfile.CRM))


class PermissionModuleImportHygieneTests(SimpleTestCase):
    def test_permissions_module_has_no_forbidden_imports(self):
        tree = ast.parse(PERMISSIONS_PATH.read_text(encoding='utf-8'), filename=str(PERMISSIONS_PATH))
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split('.')[0]
                    if root in FORBIDDEN_PROJECT_APPS:
                        violations.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split('.')[0]
                if root in FORBIDDEN_PROJECT_APPS:
                    violations.append(node.module)
        self.assertEqual(violations, [])

    def test_public_methods_are_typed(self):
        tree = ast.parse(PERMISSIONS_PATH.read_text(encoding='utf-8'), filename=str(PERMISSIONS_PATH))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == 'PermissionService':
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name in {'can_change', 'can_delete'}:
                        self.assertIsNotNone(item.returns, msg=f'{item.name} missing return annotation')
                        self.assertTrue(item.args.args, msg=f'{item.name} missing parameter annotations')
        self.assertEqual(set(ROLE_FLAG_NAMES), set(_load_baseline()['role_flags']))
