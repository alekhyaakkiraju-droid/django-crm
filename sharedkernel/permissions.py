"""Unified object-level permission resolution for CRM and attached-file profiles."""

from __future__ import annotations

import logging
from enum import Enum
from typing import Callable, Protocol

logger = logging.getLogger('sharedkernel.permissions')

ROLE_FLAG_NAMES = (
    'is_superuser',
    'is_chief',
    'is_superoperator',
    'is_operator',
    'is_manager',
    'is_accountant',
    'is_task_operator',
    'is_department_head',
)


class RuleProfile(str, Enum):
    CRM = 'crm'
    ATTACHED_FILE = 'attached_file'


class ActorLike(Protocol):
    pk: int | None

    @property
    def is_superuser(self) -> bool: ...

    @property
    def is_chief(self) -> bool: ...

    @property
    def is_superoperator(self) -> bool: ...

    @property
    def is_operator(self) -> bool: ...

    @property
    def department_id(self) -> int | None: ...


class ObjectLike(Protocol):
    pk: int | None
    owner: object | None
    department_id: int | None


Predicate = Callable[[object, object], bool]


class PermissionService:
    """Resolve object-level change/delete permission using explicit rule profiles."""

    @classmethod
    def can_change(
        cls,
        actor: object,
        obj: object,
        profile: RuleProfile | None = None,
    ) -> bool:
        selected = profile or RuleProfile.CRM
        if selected is RuleProfile.CRM:
            return _evaluate_profile(actor, obj, CRM_ALLOW_RULES)
        return _evaluate_attached_file(actor, obj)

    @classmethod
    def can_delete(
        cls,
        actor: object,
        obj: object,
        profile: RuleProfile | None = None,
    ) -> bool:
        return cls.can_change(actor, obj, profile)


def _role_flag(actor: object, name: str) -> bool:
    return bool(getattr(actor, name, False))


def _actor_id(actor: object) -> int | str | None:
    return getattr(actor, 'pk', None)


def _object_id(obj: object) -> int | str | None:
    return getattr(obj, 'pk', None)


def _model_label(obj: object) -> str:
    meta = getattr(obj, '_meta', None)
    if meta is not None:
        label = getattr(meta, 'label', None)
        if label:
            return str(label)
    return type(obj).__name__


def _role_flags(actor: object) -> dict[str, bool]:
    return {name: _role_flag(actor, name) for name in ROLE_FLAG_NAMES}


def _deny(actor: object, obj: object, rule_name: str) -> bool:
    logger.info(
        'Permission denied actor_id=%s model=%s object_id=%s rule=%s role_flags=%s',
        _actor_id(actor),
        _model_label(obj),
        _object_id(obj),
        rule_name,
        _role_flags(actor),
        extra={
            'actor_id': _actor_id(actor),
            'model_label': _model_label(obj),
            'object_id': _object_id(obj),
            'rule_name': rule_name,
            'role_flags': _role_flags(actor),
        },
    )
    return False


def _safe_match(rule_name: str, predicate: Predicate, actor: object, obj: object) -> bool:
    try:
        return predicate(actor, obj)
    except Exception:
        logger.exception(
            'Permission predicate failed actor_id=%s model=%s object_id=%s rule=%s',
            _actor_id(actor),
            _model_label(obj),
            _object_id(obj),
            rule_name,
            extra={
                'actor_id': _actor_id(actor),
                'model_label': _model_label(obj),
                'object_id': _object_id(obj),
                'rule_name': rule_name,
            },
        )
        return False


def _evaluate_profile(
    actor: object,
    obj: object,
    rules: tuple[tuple[str, Predicate], ...],
) -> bool:
    for rule_name, predicate in rules:
        if _safe_match(rule_name, predicate, actor, obj):
            return True
    return _deny(actor, obj, 'deny_default')


def _crm_elevated_role(actor: object, obj: object) -> bool:
    """Reproduces the chief / superoperator / superuser short-circuit."""
    return any(
        (
            _role_flag(actor, 'is_chief'),
            _role_flag(actor, 'is_superoperator'),
            _role_flag(actor, 'is_superuser'),
        )
    )


def _crm_operator_same_department(actor: object, obj: object) -> bool:
    """Reproduces the operator plus same-department allow branch."""
    return (
        _role_flag(actor, 'is_operator')
        and getattr(obj, 'department_id', None) == getattr(actor, 'department_id', None)
    )


def _crm_owner(actor: object, obj: object) -> bool:
    """Reproduces the owner equality branch."""
    if not hasattr(obj, 'owner'):
        return False
    return actor == obj.owner


def _crm_co_owner(actor: object, obj: object) -> bool:
    """Reproduces the owner/co_owner membership branch."""
    if not hasattr(obj, 'owner'):
        return False
    if not hasattr(obj, 'co_owner'):
        return False
    return actor in (obj.owner, obj.co_owner)


CRM_ALLOW_RULES: tuple[tuple[str, Predicate], ...] = (
    ('elevated_role', _crm_elevated_role),
    ('operator_same_department', _crm_operator_same_department),
    ('owner', _crm_owner),
    ('co_owner', _crm_co_owner),
)


def _attached_owner_branch_deny_rule(actor: object, obj: object) -> str | None:
    if hasattr(obj, 'REVIEWED') and obj.stage == obj.REVIEWED:
        return 'owner_reviewed_stage'
    if hasattr(obj, 'incoming') and obj.incoming:
        return 'owner_incoming'
    if hasattr(obj, 'uid') and obj.uid:
        return 'owner_uid_present'
    if not obj.owner and _role_flag(actor, 'is_chief'):
        return 'unowned_chief_denied'
    return None


def _attached_co_owner(actor: object, obj: object) -> bool:
    return hasattr(obj, 'co_owner') and obj.co_owner == actor


def _attached_superoperator(actor: object, obj: object) -> bool:
    return _role_flag(actor, 'is_superoperator')


def _attached_task_operator(actor: object, obj: object) -> bool:
    return _role_flag(actor, 'is_task_operator')


def _attached_superuser(actor: object, obj: object) -> bool:
    return _role_flag(actor, 'is_superuser')


def _attached_operator_same_department(actor: object, obj: object) -> bool:
    return (
        hasattr(obj, 'department')
        and _role_flag(actor, 'is_operator')
        and getattr(obj, 'department_id', None) == getattr(actor, 'department_id', None)
    )


def _attached_single_responsible(actor: object, obj: object) -> bool:
    responsible = getattr(obj, 'responsible', None)
    if responsible is None:
        return False
    return responsible.count() == 1 and actor in tuple(responsible.all())


def _attached_win_closing_chief(actor: object, obj: object) -> bool:
    return hasattr(obj, 'win_closing_date') and _role_flag(actor, 'is_chief')


ATTACHED_FILE_GRANT_RULES: tuple[tuple[str, Predicate], ...] = (
    ('co_owner', _attached_co_owner),
    ('superoperator', _attached_superoperator),
    ('task_operator', _attached_task_operator),
    ('superuser', _attached_superuser),
    ('operator_same_department', _attached_operator_same_department),
    ('single_responsible', _attached_single_responsible),
    ('win_closing_chief', _attached_win_closing_chief),
)


def _evaluate_attached_file(actor: object, obj: object) -> bool:
    """Reproduce BaseFileInline.clarify_permission decision flow."""
    if hasattr(obj, 'owner'):
        if obj.owner == actor or not obj.owner:
            deny_rule = _attached_owner_branch_deny_rule(actor, obj)
            if deny_rule is not None:
                return _deny(actor, obj, deny_rule)
            return True
    else:
        return True

    for rule_name, predicate in ATTACHED_FILE_GRANT_RULES:
        if _safe_match(rule_name, predicate, actor, obj):
            return True
    return _deny(actor, obj, 'deny_default')
