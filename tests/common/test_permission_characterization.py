"""Golden-master characterization tests for permission helper variants.

Inventory of inputs inspected by each variant:

crm.utils.clarify_permission.clarify_permission(request, obj)
- request.user.is_chief
- request.user.is_superoperator
- request.user.is_superuser
- request.user.is_operator with obj.department_id == request.user.department_id
- obj.owner compared to request.user
- obj.co_owner compared to request.user (when present)

sharedkernel.inlines.BaseFileInline.clarify_permission(request, obj)
- obj.owner compared to request.user, including unowned objects
- obj.stage versus obj.REVIEWED when REVIEWED exists on the object
- obj.incoming when present
- obj.uid when present
- request.user.is_chief for unowned objects
- obj.co_owner compared to request.user
- request.user.is_superoperator
- request.user.is_task_operator
- request.user.is_superuser
- request.user.is_operator with obj.department_id == request.user.department_id
- obj.responsible.count() and membership in obj.responsible.all()
- obj.win_closing_date combined with request.user.is_chief

crm.site.crmmodeladmin.CrmModelAdmin.has_change_permission / has_delete_permission
- super().has_change_permission result (deny-then-clarify ordering)
- clarify_permission(request, obj) only when super grants and obj is present
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory, tag
from django.urls import reverse

from common.site.basemodeladmin import BaseModelAdmin
from common.utils.helpers import USER_MODEL
from common.utils.usermiddleware import UserMiddleware
from crm.models import Deal, Stage
from crm.site.crmadminsite import crm_site
from crm.site.dealadmin import DealAdmin
from crm.site.crmmodeladmin import CrmModelAdmin
from crm.utils.clarify_permission import clarify_permission
from sharedkernel.inlines import FileInline
from tests.base_test_classes import BaseTestCase
from tests.common.permission_matrix_helpers import (
    ROLE_FLAGS,
    build_clarify_object,
    build_clarify_subject_users,
    build_file_inline_object,
    matrix_request,
    matrix_user,
)

FIXTURE_PATH = Path(__file__).resolve().parent.parent / 'fixtures' / 'permission_matrix_baseline.json'


def _request_with_role_flags(user):
    request = RequestFactory().get('/')
    request.user = user
    request.session = {}
    UserMiddleware(lambda req: None)(request)
    return request


def _load_baseline() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


@tag('TestCase')
class ClarifyPermissionCharacterizationTests(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.baseline = _load_baseline()

    def test_role_flag_inventory_matches_fixture(self):
        self.assertEqual(self.baseline['role_flags'], list(ROLE_FLAGS))

    def test_clarify_permission_matrix_matches_baseline(self):
        for row in self.baseline['clarify_permission']:
            with self.subTest(row_id=row['id']):
                actor, owner, co_owner = build_clarify_subject_users(row)
                obj = build_clarify_object(
                    membership=row['membership'],
                    department_match=row['department_match'],
                    owner=owner,
                    co_owner=co_owner,
                )
                result = clarify_permission(matrix_request(actor), obj)
                self.assertEqual(result, row['expected'])


@tag('TestCase')
class FileInlineClarifyPermissionCharacterizationTests(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.baseline = _load_baseline()

    def test_file_inline_matrix_matches_baseline(self):
        for row in self.baseline['file_inline_clarify_permission']:
            with self.subTest(row_id=row['id']):
                counter = int(row['id'].split('-')[1])
                actor = matrix_user(**row['roles'], username=f'fi-{counter}', pk=7000 + counter)
                obj = build_file_inline_object(row, actor)
                result = FileInline.clarify_permission(matrix_request(actor), obj)
                self.assertEqual(result, row['expected'])


@tag('TestCase')
class CrmModelAdminPermissionOrderingTests(BaseTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.admin = DealAdmin(Deal, AdminSite())
        self.request = self.factory.get('/')
        self.request.user = USER_MODEL.objects.get(username='Andrew.Manager.Global')
        self.obj = Deal(pk=1)

    @patch('crm.site.crmmodeladmin.clarify_permission')
    @patch.object(BaseModelAdmin, 'has_change_permission', return_value=False)
    def test_super_deny_skips_clarify_on_change(self, _mock_super, mock_clarify):
        result = CrmModelAdmin.has_change_permission(self.admin, self.request, self.obj)
        self.assertFalse(result)
        mock_clarify.assert_not_called()

    @patch('crm.site.crmmodeladmin.clarify_permission')
    @patch.object(BaseModelAdmin, 'has_delete_permission', return_value=False)
    def test_super_deny_skips_clarify_on_delete(self, _mock_super, mock_clarify):
        result = CrmModelAdmin.has_delete_permission(self.admin, self.request, self.obj)
        self.assertFalse(result)
        mock_clarify.assert_not_called()

    @patch('crm.site.crmmodeladmin.clarify_permission', return_value=True)
    @patch.object(BaseModelAdmin, 'has_change_permission', return_value=True)
    def test_super_allow_delegates_to_clarify(self, _mock_super, mock_clarify):
        result = CrmModelAdmin.has_change_permission(self.admin, self.request, self.obj)
        self.assertTrue(result)
        mock_clarify.assert_called_once_with(self.request, self.obj)


@tag('TestCase')
class DealChangeViewPermissionIntegrationTests(BaseTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.owner = USER_MODEL.objects.get(username='Darian.Manager.Co-worker.Head.Global')
        cls.other_manager = USER_MODEL.objects.get(username='Andrew.Manager.Global')
        cls.department = cls.owner.groups.filter(department__isnull=False).first()
        cls.stage = Stage.objects.filter(department=cls.department, default=True).first()

    def setUp(self):
        self.deal = Deal.objects.create(
            name='Permission characterization deal',
            next_step='Follow up',
            next_step_date='2026-08-01',
            department=self.department,
            stage=self.stage,
            owner=self.owner,
            co_owner=None,
        )
        self.change_url = reverse('site:crm_deal_change', args=(self.deal.pk,))
        self.changelist_url = reverse('site:crm_deal_changelist')

    def test_non_owner_manager_object_level_change_is_denied(self):
        request = _request_with_role_flags(self.other_manager)
        admin = DealAdmin(Deal, crm_site)
        self.assertFalse(admin.has_change_permission(request, self.deal))

    def test_non_owner_manager_deal_change_view_http_outcome(self):
        self.client.force_login(self.other_manager)
        response = self.client.get(self.change_url)
        self.assertIn(response.status_code, (200, 302, 403))
        if response.status_code == 302:
            self.assertEqual(response.url, self.changelist_url)
