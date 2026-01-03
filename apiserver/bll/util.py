import functools
import itertools
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime
from typing import (
    Optional,
    Callable,
    Iterable,
    Tuple,
    Sequence,
    TypeVar,
    Union,
)

from boltons import iterutils

from apiserver.apierrors import APIError, errors
from apiserver.database.model.auth import Role
from apiserver.database.model.project import Project
from apiserver.database.model.settings import Settings
from apiserver.service_repo.auth import Identity


@functools.lru_cache()
def get_server_uuid() -> Optional[str]:
    return Settings.get_by_key("server.uuid")


def parallel_chunked_decorator(func: Callable = None, chunk_size: int = 100):
    """
    Decorates a method for parallel chunked execution. The method should have
    one positional parameter (that is used for breaking into chunks)
    and arbitrary number of keyword params. The return value should be iterable
    The results are concatenated in the same order as the passed params
    """
    if func is None:
        return functools.partial(parallel_chunked_decorator, chunk_size=chunk_size)

    @functools.wraps(func)
    def wrapper(self, iterable: Iterable, **kwargs):
        assert iterutils.is_collection(
            iterable
        ), "The positional parameter should be an iterable for breaking into chunks"

        func_with_params = functools.partial(func, self, **kwargs)
        with ThreadPoolExecutor() as pool:
            return list(
                itertools.chain.from_iterable(
                    filter(
                        None,
                        pool.map(
                            func_with_params,
                            iterutils.chunked_iter(iterable, chunk_size),
                        ),
                    )
                ),
            )

    return wrapper


T = TypeVar("T")


def run_batch_operation(
    func: Callable[[str], T], ids: Sequence[str]
) -> Tuple[Sequence[Tuple[str, T]], Sequence[dict]]:
    results = list()
    failures = list()
    for _id in ids:
        try:
            results.append((_id, func(_id)))
        except APIError as err:
            failures.append(
                {
                    "id": _id,
                    "error": {
                        "codes": [err.code, err.subcode],
                        "msg": err.msg,
                        "data": err.error_data,
                    },
                }
            )
    return results, failures


def update_project_time(project_ids: Union[str, Sequence[str]]):
    if not project_ids:
        return

    if isinstance(project_ids, str):
        project_ids = [project_ids]

    return Project.objects(id__in=project_ids).update(last_update=datetime.utcnow())


# Roles allowed to delete any resource (admins)
ADMIN_DELETE_ROLES = {Role.system, Role.root, Role.admin, Role.superuser}


def validate_delete_permission(
    identity: Identity,
    resource_user_id: Optional[str] = None,
    resource_type: str = "resource",
) -> None:
    """
    Validates that the user has permission to delete a resource.

    Owner + Admin policy:
    - Admins (system, root, admin, superuser) can delete any resource
    - Regular users can only delete resources they own

    :param identity: The identity of the user making the request
    :param resource_user_id: The user ID of the resource owner (if available)
    :param resource_type: The type of resource being deleted (for error messages)
    :raises errors.forbidden.NoWritePermission: if the user doesn't have permission
    """
    # Admin roles can always delete
    if identity.role in ADMIN_DELETE_ROLES:
        return

    # Non-admin users can only delete their own resources
    if resource_user_id is None or identity.user != resource_user_id:
        raise errors.forbidden.NoWritePermission(
            f"only {resource_type} owner or admin can delete this {resource_type}"
        )
