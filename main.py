import os
import logging
from typing import Optional
from functools import lru_cache
import requests
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


KEYCLOAK_INTERNAL_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_EXTERNAL_URL = os.getenv("KEYCLOAK_EXTERNAL_URL", "http://localhost:8080")
REALM_NAME = os.getenv("REALM_NAME", "myrealm")

JWKS_URL = f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{KEYCLOAK_EXTERNAL_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
)

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    roles: list[str] = []



@lru_cache(maxsize=1)
def get_keycloak_public_keys():
    try:
        response = requests.get(JWKS_URL, timeout=5)
        response.raise_for_status()
        return response.json().get("keys", [])
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des clés Keycloak: {e}")
        return []


def clear_keys_cache():
    get_keycloak_public_keys.cache_clear()


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Jeton invalide, expiré ou non fourni",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise credentials_exception

        keys = get_keycloak_public_keys()
        rsa_key = next((key for key in keys if key["kid"] == kid), None)

       
        if not rsa_key:
            clear_keys_cache()
            keys = get_keycloak_public_keys()
            rsa_key = next((key for key in keys if key["kid"] == kid), None)

        if not rsa_key:
            raise credentials_exception

    
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )

        username: Optional[str] = payload.get("preferred_username")
        if username is None:
            raise credentials_exception

    
        realm_access = payload.get("realm_access", {})
        roles = realm_access.get("roles", [])

        return User(
            username=username,
            email=payload.get("email"),
            full_name=payload.get("name"),
            roles=roles,
        )

    except JWTError as e:
        logger.warning(f"Erreur de validation JWT: {e}")
        raise credentials_exception



@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_user)):
    return [{"item_id": 1, "owner": current_user.username, "roles": current_user.roles}]