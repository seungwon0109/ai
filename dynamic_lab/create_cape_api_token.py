from pathlib import Path

from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token


User = get_user_model()
user, _ = User.objects.get_or_create(
    username="cape-api",
    defaults={"email": "cape-api@localhost"},
)
user.set_unusable_password()
user.save()

token, _ = Token.objects.get_or_create(user=user)
token_path = Path("/home/cape/.cape_api_token")
token_path.write_text(token.key, encoding="ascii")
token_path.chmod(0o600)
