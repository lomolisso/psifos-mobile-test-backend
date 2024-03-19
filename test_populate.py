import json

from app.database import engine, Base
from app.api.model import crud

def main():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    from app.database import SessionLocal
    session = SessionLocal()

    # Create an election
    election = crud.create_election(
        session=session,
        fields={
            "short_name": "test_election",
            "crypto_params": json.dumps({
                "tdkg": {
                    "curve": "secp521r1",
                    "threshold": 2,
                    "num_participants": 3,
                }
            })
        }
    )

    # Create test trustees
    crud.create_trustee(
        session=session,
        fields={
            "name": "trustee_1",
            "election_uuid": election.uuid
        }
    )

    crud.create_trustee(
        session=session,
        fields={
            "name": "trustee_2",
            "election_uuid": election.uuid
        }
    )

    crud.create_trustee(
        session=session,
        fields={
            "name": "trustee_3",
            "election_uuid": election.uuid
        }
    )


if __name__ == "__main__":
    main()
