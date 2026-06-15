"""SuperTokens-Init für KyberGuard — EmailPassword + Session + SMTP."""

import os

from supertokens_python import InputAppInfo, SupertokensConfig, init
from supertokens_python.recipe import emailpassword, session
from supertokens_python.recipe.emailpassword.emaildelivery.services.smtp import SMTPService
from supertokens_python.ingredients.emaildelivery.types import SMTPSettings, SMTPSettingsFrom


def init_supertokens() -> None:
    connection_uri = os.environ.get("SUPERTOKENS_CONNECTION_URI", "http://172.18.0.4:3567")
    api_key = os.environ.get("SUPERTOKENS_API_KEY")

    smtp_host = os.environ.get("SMTP_HOST", "smtp.mailbox.org")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    smtp_from = os.environ.get("SMTP_FROM", "info@kyberguard.de")

    email_service = SMTPService(
        smtp_settings=SMTPSettings(
            host=smtp_host,
            port=smtp_port,
            from_=SMTPSettingsFrom(name="KyberGuard", email=smtp_from),
            password=smtp_pass,
            secure=False,
            username=smtp_user,
        ),
    )

    init(
        app_info=InputAppInfo(
            app_name="KyberGuard",
            api_domain="https://kyberguard.de",
            website_domain="https://kyberguard.de",
            api_base_path="/api/auth",
            website_base_path="/auth",
        ),
        supertokens_config=SupertokensConfig(
            connection_uri=connection_uri,
            api_key=api_key,
        ),
        framework="fastapi",
        recipe_list=[
            emailpassword.init(
                email_delivery=emailpassword.EmailDeliveryConfig(
                    service=email_service,
                ),
            ),
            session.init(
                cookie_secure=True,
                cookie_same_site="strict",
            ),
        ],
        mode="asgi",
    )
