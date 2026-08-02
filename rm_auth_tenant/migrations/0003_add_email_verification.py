# Generated for the community-edition signup / email-verification feature.
#
# Adds User.is_email_verified (default True -- every existing creation path
# is unaffected; only SignupView ever passes False, and only when
# RM_AUTH["SIGNUP_EMAIL_VERIFICATION_ENABLED"] is on -- see
# accounts/models.py and services/email_verification_service.py), and adds
# the three new SecurityEvent.event choices used by the signup/verification
# flow (user_signed_up, email_verification_sent, email_verified).

import drf_base_app.models.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("rm_auth_tenant", "0002_seed_system_user"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="is_email_verified",
            field=drf_base_app.models.fields.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name="securityevent",
            name="event",
            field=drf_base_app.models.fields.CharField(
                choices=[
                    ("login_success", "login_success"),
                    ("login_failure", "login_failure"),
                    ("logout", "logout"),
                    ("token_refreshed", "token_refreshed"),
                    ("password_changed", "password_changed"),
                    ("persona_switched", "persona_switched"),
                    ("role_assigned", "role_assigned"),
                    ("role_revoked", "role_revoked"),
                    ("permission_granted", "permission_granted"),
                    ("permission_revoked", "permission_revoked"),
                    ("user_signed_up", "user_signed_up"),
                    ("email_verification_sent", "email_verification_sent"),
                    ("email_verified", "email_verified"),
                ],
                max_length=32,
            ),
        ),
    ]
