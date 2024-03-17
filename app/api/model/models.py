from sqlalchemy import Column, Integer, Sequence, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base
import uuid


class Election(Base):
    __tablename__ = "psifos_election"
    uuid = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )

    short_name = Column(String, nullable=False, unique=True)
    public_key = Column(String, nullable=True)
    global_keygen_step = Column(Integer, default=0)

    # One-to-many relationships
    trustees = relationship("Trustee", cascade="all, delete", backref="psifos_election")
    key_gen_share = relationship(
        "KeyGenShare", cascade="all, delete", backref="psifos_election"
    )


class Trustee(Base):
    __tablename__ = "psifos_trustee"

    uuid = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )

    election_uuid = Column(
        UUID,
        ForeignKey("psifos_election.uuid", onupdate="CASCADE", ondelete="CASCADE"),
    )

    name = Column(String, nullable=False)

    participant_id = Column(
        Integer, Sequence("participant_id_seq", start=1), nullable=False
    )
    local_keygen_step = Column(Integer, default=0)

    certificate = Column(String, nullable=True)
    signed_broadcasts = Column(String, nullable=True)
    acknowledgements = Column(String, nullable=True)
    verification_key = Column(String, nullable=True)


class KeyGenShare(Base):
    __tablename__ = "psifos_keygen_share"

    uuid = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    election_uuid = Column(
        UUID(as_uuid=True),
        ForeignKey("psifos_election.uuid", onupdate="CASCADE", ondelete="CASCADE"),
    )

    sender = Column(Integer, nullable=False)
    receiver = Column(Integer, nullable=False)
    share = Column(String, nullable=True)
