from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    environment: str = "dev"
    gcp_project_id: str
    cloud_sql_connection_name: str
    db_name: str = "vardryn"
    db_user: str = "vardryn_app"
    db_password: str

    kms_keyring_id: str
    kms_signing_key_id: str
    # Asymmetric KMS keys sign a specific version (there is no "primary" for
    # asymmetric sign). Set this to the current enabled version after a manual
    # rotation so signing does not keep using a disabled/destroyed version.
    kms_signing_key_version: str = "1"

    evidence_bucket: str

    pubsub_audit_topic: str = ""
    pubsub_evidence_topic: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
