"""
Authenticator allowlist — Week 2.

At this stage only YubiKey 5 series / YubiKey 5 FIPS series authenticators
are accepted, identified by AAGUID.

ENGINEERING-CONFIDENCE NOTE (read before relying on this in production):
The AAGUID values below are seeded from publicly documented Yubico
identifiers and MUST be cross-checked against a freshly fetched FIDO
Alliance Metadata Service (MDS3) BLOB before this allowlist is relied on.
`fetch_mds_blob()` is a deliberate stub for that integration — it raises
NotImplementedError rather than silently returning an empty/permissive
result. Week 2 exit criteria explicitly include performing this check;
do not remove the stub's exception without implementing the JWT signature
verification against the MDS3 root CA.
"""

from __future__ import annotations

# Seeded from public Yubico documentation. VERIFY AGAINST MDS3 BEFORE
# PRODUCTION — see module docstring.
YUBIKEY_5_AAGUID_ALLOWLIST: frozenset[str] = frozenset(
    {
        "cb69481e-8ff7-4039-93ec-0a2729a154a8",  # YubiKey 5 NFC
        "ee882879-721c-4913-9775-3dfcce97072a",  # YubiKey 5C
        "fa2b99dc-9e39-4257-8f92-4a30d23c4118",  # YubiKey 5 Nano
        "c5ef55ff-ad9a-4b9f-b580-adebafe026d0",  # YubiKey 5Ci
        # YubiKey 5 FIPS series AAGUIDs intentionally omitted pending MDS3
        # verification — add only after confirming against the live blob.
    }
)


def is_allowed_aaguid(aaguid: str) -> bool:
    return aaguid.lower() in YUBIKEY_5_AAGUID_ALLOWLIST


def fetch_mds_blob(url: str = "https://mds3.fidoalliance.org/") -> dict:
    """
    STUB. Week 2 exit criteria require:
      1. Fetching the MDS3 BLOB (a signed JWT) from `url`.
      2. Verifying its signature chain against the FIDO Alliance MDS root CA.
      3. Looking up each candidate AAGUID's metadata statement and
         confirming `YUBIKEY_5_AAGUID_ALLOWLIST` matches reality.

    Deliberately unimplemented: requires network access and a vendored
    copy of the MDS3 root CA certificate, neither of which should be
    fabricated. Raises rather than returning a permissive default.
    """
    raise NotImplementedError(
        "fetch_mds_blob is a Week 2 integration point. Implement against "
        f"{url} with JWT signature verification against the FIDO Alliance "
        "MDS root CA before relying on YUBIKEY_5_AAGUID_ALLOWLIST in "
        "production."
    )
