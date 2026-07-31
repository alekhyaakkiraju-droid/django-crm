"""Generate permission decision-matrix fixtures for characterization tests."""

from __future__ import annotations

import itertools
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'webcrm.settings')

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

FILE_INLINE_OWNER_STAGE = ('pending', 'reviewed', 'no_reviewed_attr')
FILE_INLINE_INCOMING = ('absent', 'false', 'true')
FILE_INLINE_UID = ('absent', 'present')
FILE_INLINE_OWNERSHIP = ('owner_self', 'no_owner', 'co_owner', 'other')
FILE_INLINE_RESPONSIBLE = (
    'absent',
    'single_includes_user',
    'single_excludes_user',
    'multiple',
)
FILE_INLINE_WIN_CLOSING = ('absent', 'present')


def _role_combinations() -> list[dict[str, bool]]:
    combos = []
    for bits in itertools.product((False, True), repeat=len(ROLE_FLAGS)):
        combos.append(dict(zip(ROLE_FLAGS, bits)))
    return combos


def _user(**kwargs):
    from types import SimpleNamespace

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


def _request(user):
    from types import SimpleNamespace

    return SimpleNamespace(user=user)


def _build_clarify_object(membership: str, department_match: bool, owner, co_owner):
    from types import SimpleNamespace

    department_id = 10 if department_match else 20
    return SimpleNamespace(
        owner=owner,
        co_owner=co_owner,
        department_id=department_id,
    )


def _build_file_inline_object(
    *,
    ownership: str,
    stage_mode: str,
    incoming_mode: str,
    uid_mode: str,
    responsible_mode: str,
    win_closing_mode: str,
    department_match: bool,
    actor,
    owner,
    co_owner,
):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    obj = SimpleNamespace(
        owner=owner,
        department=True,
        department_id=10 if department_match else 20,
    )

    if ownership == 'no_owner':
        obj.owner = None
    elif ownership == 'co_owner':
        obj.co_owner = co_owner
    elif ownership == 'owner_self':
        obj.co_owner = None
    else:
        obj.co_owner = co_owner

    if stage_mode == 'pending':
        obj.stage = 'pen'
        obj.REVIEWED = 'rev'
    elif stage_mode == 'reviewed':
        obj.stage = 'rev'
        obj.REVIEWED = 'rev'
    # no_reviewed_attr: omit REVIEWED/stage

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
            responsible.all.return_value = [_user(username='someone-else', pk=1002)]
        else:
            responsible.count.return_value = 2
            responsible.all.return_value = [actor, _user(username='someone-else', pk=1002)]
        obj.responsible = responsible

    return obj


def generate_clarify_permission_matrix() -> list[dict]:
    from crm.utils.clarify_permission import clarify_permission as crm_clarify_permission

    rows = []
    counter = 0
    owner_user = _user(username='owner-user', pk=2001)
    co_owner_user = _user(username='co-owner-user', pk=2002)
    other_user = _user(username='other-user', pk=2003)

    for roles in _role_combinations():
        for membership in MEMBERSHIPS:
            for department_match in DEPARTMENT_MATCHES:
                counter += 1
                if membership == 'owner':
                    actor = _user(**roles, username=f'actor-{counter}', pk=3000 + counter)
                    subject = actor
                    co_owner = None
                elif membership == 'co_owner':
                    actor = _user(**roles, username=f'actor-{counter}', pk=3000 + counter)
                    subject = owner_user
                    co_owner = actor
                else:
                    actor = _user(**roles, username=f'actor-{counter}', pk=3000 + counter)
                    subject = owner_user
                    co_owner = co_owner_user

                obj = _build_clarify_object(membership, department_match, subject, co_owner)
                request = _request(actor)
                expected = crm_clarify_permission(request, obj)
                rows.append(
                    {
                        'id': f'cp-{counter:04d}',
                        'roles': roles,
                        'membership': membership,
                        'department_match': department_match,
                        'expected': expected,
                    }
                )
    return rows


def generate_file_inline_matrix() -> list[dict]:
    from sharedkernel.inlines import BaseFileInline

    rows = []
    counter = 0
    owner_user = _user(username='owner-user', pk=4001)
    co_owner_user = _user(username='co-owner-user', pk=4002)

    neutral_roles = {flag: False for flag in ROLE_FLAGS}
    chief_roles = {**neutral_roles, 'is_chief': True}

    owner_path = itertools.product(
        FILE_INLINE_OWNER_STAGE,
        FILE_INLINE_INCOMING,
        FILE_INLINE_UID,
    )
    for stage_mode, incoming_mode, uid_mode in owner_path:
        counter += 1
        actor = _user(**neutral_roles, username=f'fi-owner-self-{counter}', pk=5000 + counter)
        obj = _build_file_inline_object(
            ownership='owner_self',
            stage_mode=stage_mode,
            incoming_mode=incoming_mode,
            uid_mode=uid_mode,
            responsible_mode='absent',
            win_closing_mode='absent',
            department_match=True,
            actor=actor,
            owner=owner_user,
            co_owner=None,
        )
        obj.owner = actor
        request = _request(actor)
        rows.append(
            {
                'id': f'fi-{counter:04d}',
                'variant': 'owner_path',
                'roles': neutral_roles,
                'ownership': 'owner_self',
                'stage': stage_mode,
                'incoming': incoming_mode,
                'uid': uid_mode,
                'responsible': 'absent',
                'win_closing_date': 'absent',
                'department_match': True,
                'expected': BaseFileInline.clarify_permission(request, obj),
            }
        )

    for stage_mode, incoming_mode, uid_mode in owner_path:
        for roles, label in ((neutral_roles, 'non_chief'), (chief_roles, 'chief')):
            counter += 1
            actor = _user(**roles, username=f'fi-no-owner-{label}-{counter}', pk=5100 + counter)
            obj = _build_file_inline_object(
                ownership='no_owner',
                stage_mode=stage_mode,
                incoming_mode=incoming_mode,
                uid_mode=uid_mode,
                responsible_mode='absent',
                win_closing_mode='absent',
                department_match=True,
                actor=actor,
                owner=None,
                co_owner=None,
            )
            request = _request(actor)
            rows.append(
                {
                    'id': f'fi-{counter:04d}',
                    'variant': 'owner_path',
                    'roles': roles,
                    'ownership': 'no_owner',
                    'stage': stage_mode,
                    'incoming': incoming_mode,
                    'uid': uid_mode,
                    'responsible': 'absent',
                    'win_closing_date': 'absent',
                    'department_match': True,
                    'expected': BaseFileInline.clarify_permission(request, obj),
                }
            )

    non_owner_variants = itertools.product(
        FILE_INLINE_OWNERSHIP,
        FILE_INLINE_RESPONSIBLE,
        FILE_INLINE_WIN_CLOSING,
        DEPARTMENT_MATCHES,
    )
    for ownership, responsible_mode, win_closing_mode, department_match in non_owner_variants:
        if ownership not in ('co_owner', 'other'):
            continue
        for roles in _role_combinations():
            counter += 1
            actor = _user(**roles, username=f'fi-other-{counter}', pk=6000 + counter)
            obj = _build_file_inline_object(
                ownership=ownership,
                stage_mode='pending',
                incoming_mode='false',
                uid_mode='absent',
                responsible_mode=responsible_mode,
                win_closing_mode=win_closing_mode,
                department_match=department_match,
                actor=actor,
                owner=owner_user,
                co_owner=actor if ownership == 'co_owner' else None,
            )
            request = _request(actor)
            rows.append(
                {
                    'id': f'fi-{counter:04d}',
                    'variant': 'non_owner_path',
                    'roles': roles,
                    'ownership': ownership,
                    'stage': 'pending',
                    'incoming': 'false',
                    'uid': 'absent',
                    'responsible': responsible_mode,
                    'win_closing_date': win_closing_mode,
                    'department_match': department_match,
                    'expected': BaseFileInline.clarify_permission(request, obj),
                }
            )

    return rows


def main() -> None:
    fixture_path = Path(__file__).resolve().parent.parent / 'fixtures' / 'permission_matrix_baseline.json'
    payload = {
        'schema_version': 1,
        'role_flags': list(ROLE_FLAGS),
        'clarify_permission': generate_clarify_permission_matrix(),
        'file_inline_clarify_permission': generate_file_inline_matrix(),
    }
    fixture_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')
    print(
        f'Wrote {len(payload["clarify_permission"])} clarify_permission rows and '
        f'{len(payload["file_inline_clarify_permission"])} file_inline rows to {fixture_path}'
    )


if __name__ == '__main__':
    sys.argv = [sys.argv[0], 'test']
    import django

    django.setup()
    main()
