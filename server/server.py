from fastmcp import FastMCP, Context
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.dependencies import get_access_token
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import requests
import base64
from oci.config import validate_config
import oci
import jwt
import os


IDCS_DOMAIN = os.getenv("IDCS_DOMAIN")
IDCS_CLIENT_ID = os.getenv("IDCS_CLIENT_ID")
IDCS_CLIENT_SECRET = os.getenv("IDCS_CLIENT_SECRET")


def get_token_endpoint(domain: str) -> str:
    config_url = f"https://{domain}/.well-known/openid-configuration"
    response = requests.get(config_url)
    response.raise_for_status()
    return response.json()["token_endpoint"]


def generate_config(upst: bytes, private_key: rsa.RSAPrivateKey, region: str) -> dict:
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_pem_b64 = base64.b64encode(private_key_pem).decode("utf-8")

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # TODO: ⚠️ FIX VERIFICATION, this should not be disabled
    decoded_upst = jwt.decode(
        upst, public_key_pem, algorithms=["RS256"], options={"verify_signature": False}
    )

    digest = hashes.Hash(hashes.MD5())
    digest.update(private_key_pem)
    fingerprint = digest.finalize()
    fingerprint_hex = ":".join(f"{b:02x}" for b in fingerprint)

    config = {
        "user": decoded_upst["sub"],
        "key_content": private_key_pem_b64,
        "fingerprint": fingerprint_hex,
        "tenancy": decoded_upst["tenant"],
        "region": region,
    }
    validate_config(config)
    return config


def get_identity_client(token, private_key):
    # TODO: fix hard-coded region here
    # the region can be pulled from the decoded JWT (not the UPST),
    # field "domain_home"
    config = generate_config(token, private_key, "us-sanjose-1")
    signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
    return oci.identity.IdentityClient(config, signer=signer)


def exchange_token(client_id, client_secret, public_key, jwt):
    """Exchange a JWT for a UPST"""
    creds = f"{client_id}:{client_secret}".encode("utf-8")
    encoded_creds = base64.b64encode(creds).decode("utf-8")

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:oci:token-type:oci-upst",
        "public_key": public_key,
        "subject_token": jwt,
        "subject_token_type": "jwt",
    }

    token_endpoint = get_token_endpoint(IDCS_DOMAIN)

    response = requests.post(
        token_endpoint,
        data=payload,
        headers={
            "Authorization": f"Basic {encoded_creds}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    return response.json()


auth = OIDCProxy(
    config_url=f"https://{IDCS_DOMAIN}/.well-known/openid-configuration",
    client_id=IDCS_CLIENT_ID,
    client_secret=IDCS_CLIENT_SECRET,
    # FastMCP endpoint
    base_url="http://localhost:5000",
    # audience=IDCS_CLIENT_ID,
    required_scopes=["openid"],
    # redirect_path="/custom/callback",
)

mcp = FastMCP(name="My Server", auth=auth)


@mcp.tool
def list_regions(ctx: Context):
    token = get_access_token()

    # TODO(rg): creating a new key pair on every tool invocation
    # is inefficient at best. Fix this
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    public_key = private_key.public_key()

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_key_der_b64 = base64.b64encode(public_key_der).decode("utf-8")

    print("session token:")
    print(token.token)

    upst = exchange_token(
        IDCS_CLIENT_ID, IDCS_CLIENT_SECRET, public_key_der_b64, token.token
    )["token"]
    client = get_identity_client(upst, private_key)

    return client.list_regions().data


mcp.run(transport="http", host="localhost", port=5000)
