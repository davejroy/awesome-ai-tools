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

    evidence_bucket: str

    pubsub_audit_topic: str = ""
    pubsub_evidence_topic: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
