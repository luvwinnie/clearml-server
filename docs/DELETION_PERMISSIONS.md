# ClearML Server Deletion Permissions

This document describes the role-based deletion restrictions implemented in the ClearML server.

## Overview

By default, any user within the same company (team) can delete any resource. This modification adds **Owner + Admin** deletion restrictions to protect resources from accidental or unauthorized deletion.

## Permission Model

### Owner + Admin Policy

- **Admin roles** (system, root, admin, superuser) can delete any resource
- **Regular users** (user, annotator, guest) can only delete resources they own
- **Queues** have no owner, so only admins can delete them

### Role Hierarchy

| Role | Can Delete Own Resources | Can Delete Others' Resources |
|------|-------------------------|------------------------------|
| system | ✅ | ✅ |
| root | ✅ | ✅ |
| admin | ✅ | ✅ |
| superuser | ✅ | ✅ |
| user | ✅ | ❌ |
| annotator | ✅ | ❌ |
| guest | ✅ | ❌ |

## Authentik OIDC Group-to-Role Mapping

When using Authentik for SSO, user roles are automatically assigned based on their Authentik groups.

### Group Mapping (case-insensitive)

| Authentik Group | ClearML Role |
|-----------------|--------------|
| `clearml-admins` or `admins` | admin |
| `clearml-superusers` or `superusers` | superuser |
| `clearml-users` or `users` | user |
| `clearml-annotators` or `annotators` | annotator |
| `clearml-guests` or `guests` | guest |

### Setup in Authentik

1. Create groups in Authentik (e.g., `clearml-admins`, `clearml-users`)
2. Add users to appropriate groups
3. In Authentik Provider settings, ensure `groups` scope is included
4. Users' roles will update automatically on each login

### Priority

If a user belongs to multiple groups, the highest privilege wins:
`admin > superuser > user > annotator > guest`

## Protected Resources

The following resources are now protected by deletion permissions:

1. **Tasks/Experiments** - Only owner or admin can delete
2. **Models** - Only owner or admin can delete
3. **Projects** - Only owner or admin can delete
4. **Datasets** - Protected via Tasks (datasets are tasks with special tags)
5. **Pipelines** - Protected via Tasks (pipeline runs are tasks)
6. **Reports** - Only owner or admin can delete
7. **Queues** - Only admins can delete (queues have no owner)

## Error Messages

When a user tries to delete a resource they don't own, they'll receive:

```
forbidden (modification not allowed): only <resource_type> owner or admin can delete this <resource_type>
```

## Files Modified

### Core Utility
- `apiserver/bll/util.py` - Added `validate_delete_permission()` function

### Tasks
- `apiserver/bll/task/task_operations.py` - Added permission check in `delete_task()`

### Models
- `apiserver/bll/model/__init__.py` - Added permission check in `delete_model()`
- `apiserver/services/models.py` - Updated to pass `identity` instead of `user_id`

### Projects
- `apiserver/bll/project/project_cleanup.py` - Added permission check in `delete_project()`
- `apiserver/services/projects.py` - Updated to pass `identity` instead of `user`

### Queues
- `apiserver/bll/queue/queue_bll.py` - Added permission check in `delete()`
- `apiserver/services/queues.py` - Updated to pass `identity` instead of `user_id`

### Reports
- `apiserver/services/reports.py` - Added permission check in `delete()`

## Configuration

The admin roles allowed to delete any resource are defined in `apiserver/bll/util.py`:

```python
ADMIN_DELETE_ROLES = {Role.system, Role.root, Role.admin, Role.superuser}
```

To modify which roles can delete any resource, update this set.

## Reverting Changes

To revert to the original behavior (any user can delete any resource):

1. Remove the `validate_delete_permission()` calls from each modified file
2. Restore the original function signatures (changing `identity` back to `user_id` where applicable)
