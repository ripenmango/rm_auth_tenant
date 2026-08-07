# Hand-written to match what `makemigrations` would generate from
# rm_auth_tenant.authorization.entity_access_models.EntityAccessGrant --
# index names below are the real TenantIndex-derived names (see
# drf_base_app.models.indexes._safe_name), not placeholders, so a future
# `makemigrations` run sees no drift and produces an empty diff.

import django.db.models.deletion
import drf_base_app.models.fields
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("rm_auth_tenant", "0002_seed_system_user"),
    ]

    operations = [
        migrations.CreateModel(
            name="EntityAccessGrant",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "tenant_id",
                    drf_base_app.models.fields.CharField(db_index=True, max_length=64),
                ),
                ("entity_type", drf_base_app.models.fields.CharField(max_length=64)),
                ("entity_id", drf_base_app.models.fields.CharField(max_length=64)),
                (
                    "user_id",
                    drf_base_app.models.fields.BigIntegerField(db_index=True),
                ),
                (
                    "role",
                    drf_base_app.models.fields.CharField(
                        choices=[
                            ("viewer", "Viewer"),
                            ("editor", "Editor"),
                            ("owner", "Owner"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        related_name="%(app_label)s_%(class)s_created_by_records",
                        related_query_name="%(app_label)s_%(class)s_created_by",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        related_name="%(app_label)s_%(class)s_updated_by_records",
                        related_query_name="%(app_label)s_%(class)s_updated_by",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "rm_auth_entity_access_grant",
            },
        ),
        migrations.AddIndex(
            model_name="entityaccessgrant",
            index=models.Index(
                fields=["tenant_id", "entity_type", "entity_id"],
                name="idx_tenant_id_entity__0270d5a3",
            ),
        ),
        migrations.AddIndex(
            model_name="entityaccessgrant",
            index=models.Index(
                fields=["tenant_id", "entity_type", "user_id"],
                name="idx_tenant_id_entity__9a8251ad",
            ),
        ),
        migrations.AddConstraint(
            model_name="entityaccessgrant",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "entity_type", "entity_id", "user_id"),
                name="uniq_entity_access_grant",
            ),
        ),
    ]
