import oci
import requests
import os
from oci.identity_domains.models import IdentityPropagationTrust

IDCS_CLIENT_ID = os.getenv("IDCS_CLIENT_ID")
IDCS_DOMAIN = os.getenv("IDCS_DOMAIN")


def get_domain_config(domain: str) -> dict:
    response = requests.get(
        f"https://{domain}/.well-known/openid-configuration"
    )
    return response.json()


config = oci.config.from_file(
    profile_name=os.getenv("OCI_CONFIG_PROFILE", oci.config.DEFAULT_PROFILE)
)

private_key = oci.signer.load_private_key_from_file(config["key_file"])
token_file = config["security_token_file"]
token = None
with open(token_file, "r") as f:
    token = f.read()
signer = oci.auth.signers.SecurityTokenSigner(token, private_key)

identity_domains_client = oci.identity_domains.IdentityDomainsClient(
    config, signer=signer, service_endpoint=f"https://{IDCS_DOMAIN}"
)

domain_config = get_domain_config(IDCS_DOMAIN)

response = identity_domains_client.create_identity_propagation_trust(
    identity_propagation_trust=IdentityPropagationTrust(
        active=True,
        allow_impersonation=False,
        issuer=domain_config["issuer"],
        name="JWT-to-UPST propagation",
        oauth_clients=[
            IDCS_CLIENT_ID,
        ],
        # public_certificate="EXAMPLE-publicCertificate-Value",
        public_key_endpoint=domain_config["jwks_uri"],
        client_claim_name="client_id",
        client_claim_values=[
            IDCS_CLIENT_ID,
        ],
        subject_claim_name="sub",
        subject_mapping_attribute="userName",
        subject_type="User",
        type=IdentityPropagationTrust.TYPE_JWT,
        schemas=[
            "urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust",  # noqa: E501
        ],
    ),
)

print(response.data)
