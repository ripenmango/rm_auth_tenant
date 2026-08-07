"""
Orphan cleanup for EntityAccessGrant: since `entity_id` is a plain string,
not an enforced ForeignKey (see EntityAccessGrant's docstring for why), a
grant can outlive its target if that target is ever HARD-deleted. This
module is the mitigation -- a post_delete receiver that purges matching
grants whenever a real DELETE actually happens.

Deliberately NOT wired to every model's ordinary `.delete()` -- that's
soft-delete (RMSoftDeleteModel.delete() just sets deleted_at, no row is
removed, no post_delete fires), and grants on a soft-deleted-but-restorable
entity should stay intact so an undelete also restores who it was shared
with. Only `.hard_delete()` issues a real Django DELETE and fires
post_delete -- see RMSoftDeleteModel.hard_delete in drf_base_app.

Registration is opt-in per model (connect_hard_delete_cleanup below), not
automatic for every RMSoftDeleteModel in the project -- a model only needs
this if something can actually hold an EntityAccessGrant against it
(entity_type match), and requiring an explicit call keeps that list
visible/greppable in one place (see rm_workflow's apps.py) rather than
silently applying to models that were never shareable in the first place.
"""
from django.db.models.signals import post_delete

from rm_auth_tenant.authorization.access_scope import EntityAccessService


def _purge_grants(sender, instance, entity_type: str, **kwargs) -> None:
    EntityAccessService().purge_for_entity(
        tenant_id=instance.tenant_id,
        entity_type=entity_type,
        entity_id=instance.public_id,
    )


def connect_hard_delete_cleanup(model, entity_type: str) -> None:
    """Call once per shareable model, typically from that model's owning
    app's AppConfig.ready() -- e.g.:

        # rm_workflow/apps.py
        def ready(self):
            from rm_auth_tenant.authorization.signals import connect_hard_delete_cleanup
            from rm_workflow.workflows.models import Workflow
            from rm_workflow.workspaces.models import Workspace
            connect_hard_delete_cleanup(Workflow, "workflow")
            connect_hard_delete_cleanup(Workspace, "workspace")

    `model` must have both `tenant_id` and `public_id` fields (RMAuditModel
    + RMPublicIdModel) -- the same two identifiers EntityAccessGrant keys
    on everywhere else in this package.
    """
    post_delete.connect(
        lambda sender, instance, **kwargs: _purge_grants(sender, instance, entity_type, **kwargs),
        sender=model,
        dispatch_uid=f"entity_access_grant_cleanup__{entity_type}",
        weak=False,
    )
