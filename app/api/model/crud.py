from sqlalchemy.orm import Session
from app.api.model import models
from sqlalchemy import select, update, delete

# --- Election ---

def read_election_by_short_name(session: Session, short_name: str) -> models.Election:
    query = select(models.Election).where(
        models.Election.short_name == short_name
    )
    result = session.execute(query)
    return result.scalars().first()

def create_election(session: Session, fields: dict) -> models.Election:
    db_instance = models.Election(**fields)
    session.add(db_instance)
    session.commit()
    session.refresh(db_instance)
    return db_instance

def update_election_by_short_name(session: Session, short_name: str, fields: dict) -> models.Election:
    query = update(models.Election).where(
        models.Election.short_name == short_name
    ).values(fields)
    session.execute(query)
    session.commit()
    return read_election_by_short_name(session=session, short_name=short_name)

# --- Trustee ---

def read_trustee_by_uuid(session: Session, uuid) -> models.Trustee:
    query = select(models.Trustee).where(
        models.Trustee.uuid == uuid
    )
    result = session.execute(query)
    return result.scalars().first()

def read_trustee_by_name_and_election_short_name(session: Session, name: str, election_short_name: str) -> models.Trustee:
    query = select(models.Trustee).join(models.Election).where(
        models.Trustee.name == name
    ).where(
        models.Election.short_name == election_short_name
    )
    result = session.execute(query)
    return result.scalars().first()

def create_trustee(session: Session, fields: dict) -> models.Trustee:
    db_instance = models.Trustee(**fields)
    session.add(db_instance)
    session.commit()
    session.refresh(db_instance)
    return db_instance

def update_trustee_by_uuid(session: Session, uuid: str, fields: dict) -> models.Trustee:
    query = update(models.Trustee).where(
        models.Trustee.uuid == uuid
    ).values(fields)
    session.execute(query)
    session.commit()
    return read_trustee_by_uuid(session=session, uuid=uuid)

# --- KeyGenShare ---
def read_keygen_share_by_uuid(session: Session, uuid) -> models.KeyGenShare:
    query = select(models.KeyGenShare).where(
        models.KeyGenShare.uuid == uuid
    )
    result = session.execute(query)
    return result.scalars().first()

def read_keygen_shares_by_sender_and_election_short_name(session: Session, sender: int, election_short_name: str) -> models.KeyGenShare:
    query = select(models.KeyGenShare).join(models.Election).where(
        models.KeyGenShare.sender == sender
    ).where(
        models.Election.short_name == election_short_name
    )
    result = session.execute(query)
    return result.scalars().all()

def read_keygen_shares_by_receiver_and_election_short_name(session: Session, receiver: int, election_short_name: str) -> models.KeyGenShare:
    query = select(models.KeyGenShare).join(models.Election).where(
        models.KeyGenShare.receiver == receiver
    ).where(
        models.Election.short_name == election_short_name
    )
    return session.execute(query).scalars().all()

def create_keygen_share(session: Session, fields: dict) -> models.KeyGenShare:
    db_instance = models.KeyGenShare(**fields)
    session.add(db_instance)
    session.commit()
    session.refresh(db_instance)
    return db_instance

def update_keygen_share_by_uuid(session: Session, uuid: str, fields: dict) -> models.KeyGenShare:
    query = update(models.KeyGenShare).where(
        models.KeyGenShare.uuid == uuid
    ).values(fields)
    session.execute(query)
    session.commit()
    return read_keygen_share_by_uuid(session=session, uuid=uuid)

def delete_keygen_shares_by_receiver_and_election_short_name(session: Session, receiver: int, election_short_name: str) -> None:
    query = delete(models.KeyGenShare).where(
        models.KeyGenShare.receiver == receiver
    ).where(
        models.Election.short_name == election_short_name
    )
    session.execute(query)
    session.commit()

def delete_keygen_shares_by_sender_and_election_short_name(session: Session, sender: int, election_short_name: str) -> None:
    query = delete(models.KeyGenShare).where(
        models.KeyGenShare.sender == sender
    ).where(
        models.Election.short_name == election_short_name
    )
    session.execute(query)
    session.commit()