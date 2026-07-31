"""Shared helpers for permission characterization matrix tests."""

from __future__ import annotations

import itertools
from types import SimpleNamespace
from unittest.mock import MagicMock

ROLE_FLAGS = (
    'is_superuser',
    'is_chief',
    'is_superoperator',
    'is_operator',
    'is_manager',
    'is_accountant',
    'is_task_operator',
    'is_department_head',
)

MEMBERSHIPS = ('owner', 'co_owner', 'other')
DEPARTMENT_MATCHES = (True, False)


def role_combinations() -> list[dict[str, bool]]:
    combos = []
    for bits in itertools.product((False, True), repeat=len(ROLE_FLAGS)):
        combos.append(dict(zip(ROLE_FLAGS, bits)))
    return combos


def matrix_user(**kwargs):
    defaults = {
        'username': 'matrix-user',
        'pk': 1001,
        'department_id': 10,
        'is_superuser': False,
        'is_chief': False,
        'is_superoperator': False,
        'is_operator': False,
        'is_manager': False,
        'is_accountant': False,
        'is_task_operator': False,
        'is_department_head': False,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def matrix_request(user):
    return SimpleNamespace(user=user)


def build_clarify_object(*, membership: str, department_match: bool, owner, co_owner):
    department_id = 10 if department_match else 20
    return SimpleNamespace(
        owner=owner,
        co_owner=co_owner,
        department_id=department_id,
    )


def build_clarify_subject_users(row: dict):
    owner_user = matrix_user(username='owner-user', pk=2001)
    co_owner_user = matrix_user(username='co-owner-user', pk=2002)
    counter = row['id']
    roles = row['roles']
    membership = row['membership']

    if membership == 'owner':
        actor = matrix_user(**roles, username=f'actor-{counter}', pk=3000 + int(counter.split('-')[1]))
        return actor, actor, None
    if membership == 'co_owner':
        actor = matrix_user(**roles, username=f'actor-{counter}', pk=3000 + int(counter.split('-')[1]))
        return actor, owner_user, actor
    actor = matrix_user(**roles, username=f'actor-{counter}', pk=3000 + int(counter.split('-')[1]))
    return actor, owner_user, co_owner_user


def build_file_inline_object(row: dict, actor):
    owner_user = matrix_user(username='owner-user', pk=4001)
    co_owner_user = matrix_user(username='co-owner-user', pk=4002)
    ownership = row['ownership']
    stage_mode = row['stage']
    incoming_mode = row['incoming']
    uid_mode = row['uid']
    responsible_mode = row['responsible']
    win_closing_mode = row['win_closing_date']
    department_match = row['department_match']

    obj = SimpleNamespace(
        owner=owner_user,
        department=True,
        department_id=10 if department_match else 20,
    )

    if ownership == 'no_owner':
        obj.owner = None
    elif ownership == 'owner_self':
        obj.owner = actor
        obj.co_owner = None
    elif ownership == 'co_owner':
        obj.owner = owner_user
        obj.co_owner = actor
    else:
        obj.owner = owner_user
        obj.co_owner = co_owner_user

    if stage_mode == 'pending':
        obj.stage = 'pen'
        obj.REVIEWED = 'rev'
    elif stage_mode == 'reviewed':
        obj.stage = 'rev'
        obj.REVIEWED = 'rev'

    if incoming_mode == 'true':
        obj.incoming = True
    elif incoming_mode == 'false':
        obj.incoming = False

    if uid_mode == 'present':
        obj.uid = 'imported-uid'

    if win_closing_mode == 'present':
        obj.win_closing_date = True

    if responsible_mode != 'absent':
        responsible = MagicMock()
        if responsible_mode == 'single_includes_user':
            responsible.count.return_value = 1
            responsible.all.return_value = [actor]
        elif responsible_mode == 'single_excludes_user':
            responsible.count.return_value = 1
            responsible.all.return_value = [matrix_user(username='someone-else', pk=1002)]
        else:
            responsible.count.return_value = 2
            responsible.all.return_value = [actor, matrix_user(username='someone-else', pk=1002)]
        obj.responsible = responsible

    return obj
