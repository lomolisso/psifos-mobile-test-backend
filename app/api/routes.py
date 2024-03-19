import json

from fastapi import APIRouter, Depends
from app.dependencies import get_session
from app.api.model import schemas, crud

from Crypto.PublicKey import ECC

api_router = APIRouter()


# --- t-DKG params ---
@api_router.get("/{short_name}/get-tdkg-params", status_code=200)
async def get_crypto_params(short_name: str, session=Depends(get_session)):
    election = crud.read_election_by_short_name(session=session, short_name=short_name)
    return json.loads(election.crypto_params)["tdkg"]

@api_router.get(
    "/{election_short_name}/trustee/{trustee_name}/get-participant-id", status_code=200
)
async def get_participant_id(
    election_short_name: str, trustee_name: str, session=Depends(get_session)
):
    """
    Get the participant id of the trustee
    """
    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )
    return {
        "message": "The participant id was retrieved successfully",
        "participant_id": trustee.participant_id,
    }

@api_router.get("/{election_short_name}/get-global-keygen-step", status_code=200)
async def get_step(election_short_name: str, session=Depends(get_session)):
    """
    Get the election global keygen step
    """
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    return {
        "message": "The global keygen step was retrieved successfully",
        "global_keygen_step": election.global_keygen_step,
    }

@api_router.post(
    "/{election_short_name}/trustee/{trustee_name}/upload-cert", status_code=200
)
async def trustee_upload_cert(
    election_short_name: str,
    trustee_name: str,
    trustee_data: schemas.CertificateIn,
    session=Depends(get_session),
):
    """
    Upload the certificate of the trustee
    """
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    if election.global_keygen_step != 0:
        return {"message": "The election is not in step 0"}

    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )

    sig, keys = trustee_data.signature, json.loads(trustee_data.json_encoded_keys)
    # TODO: verify signature, if valid then update certificate
    valid = True
    if not valid:
        return {"message": "The signature is not valid"}

    # update trustee
    trustee = crud.update_trustee_by_uuid(
        session=session,
        uuid=trustee.uuid,
        fields={
            "local_keygen_step": 1,
            "certificate": json.dumps(trustee_data.model_dump()),
        },
    )

    # if all trustees have uploaded their certificates, update global keygen step
    if all(trustee.local_keygen_step == 1 for trustee in election.trustees):
        crud.update_election_by_short_name(
            session=session,
            short_name=election_short_name,
            fields={"global_keygen_step": 1},
        )

    return {"message": "The certificate was uploaded successfully"}


# - Synchronization -

# --- step 1 ---


@api_router.get("/{election_short_name}/trustee/{trustee_name}/step-1", status_code=200)
async def get_trustee_step_1(
    election_short_name: str, trustee_name: str, session=Depends(get_session)
):
    """
    GET step 1 of the keygenerator trustee
    """
    # make sure that the election is in step 1
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    if election.global_keygen_step != 1:
        return {"message": "The election is not in step 1"}

    # make sure that the trustee is in step 1
    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )
    if trustee.local_keygen_step != 1:
        return {"message": "The trustee is not in step 1"}

    # retrieve all certificates
    certificates = []
    sorted_trustees = sorted(election.trustees, key=lambda t: t.participant_id)
    for trustee in sorted_trustees:
        _cert = json.loads(trustee.certificate)
        _keys = json.loads(_cert["json_encoded_keys"])
        encryption_public_key = schemas.RSAPublicKey(**_keys["encryption_public_key"])
        signature_public_key = schemas.ECPublicKey(**_keys["signature_public_key"])
        signature = schemas.ECSignature(**_cert["signature"])
        certificates.append(
            schemas.CertificateOut(
                encryption_public_key=encryption_public_key,
                signature_public_key=signature_public_key,
                signature=signature,
            )
        )
    return schemas.TrusteeCertificates(certificates=certificates)


@api_router.post(
    "/{election_short_name}/trustee/{trustee_name}/step-1", status_code=200
)
async def post_trustee_step_1(
    election_short_name: str,
    trustee_name: str,
    trustee_data: schemas.KeyGenStep1Data,
    session=Depends(get_session),
):
    """
    POST step 1 of the keygenerator trustee
    """
    # make sure that the election is in step 1
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    if election.global_keygen_step != 1:
        return {"message": "The election is not in step 1"}

    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )

    # delete any previous shares
    crud.delete_keygen_shares_by_sender_and_election_short_name(
        session=session,
        sender=trustee.participant_id,
        election_short_name=election_short_name,
    )

    # save the signed shares
    signed_encrypted_shares = trustee_data.signed_shares
    assert len(signed_encrypted_shares) == len(election.trustees)
    for receiver_id, share in enumerate(signed_encrypted_shares, start=1):
        crud.create_keygen_share(
            session=session,
            fields={
                "election_uuid": election.uuid,
                "sender": trustee.participant_id,
                "receiver": receiver_id,
                "share": json.dumps(share.model_dump()),
            },
        )

    # parse the signed broadcasts
    _sign_broadcasts = [sb.model_dump() for sb in trustee_data.signed_broadcasts]
    parsed_signed_broadcasts = []
    for sb in _sign_broadcasts:
        x, y = sb["broadcast"][1:-1].split(",")
        parsed_signed_broadcasts.append(
            {
                "broadcast": {"x": x, "y": y},
                "signature": sb["signature"],
            }
        )

    # save the signed broadcasts
    trustee = crud.update_trustee_by_uuid(
        session=session,
        uuid=trustee.uuid,
        fields={
            "local_keygen_step": 2,
            "signed_broadcasts": json.dumps(parsed_signed_broadcasts),
        },
    )

    # if all trustees have uploaded their signed broadcasts, update global keygen step
    if all(trustee.local_keygen_step == 2 for trustee in election.trustees):
        crud.update_election_by_short_name(
            session=session,
            short_name=election_short_name,
            fields={"global_keygen_step": 2},
        )

    return {"message": "Keygenerator step 1 completed successfully"}


# --- step 2 ---


@api_router.get("/{election_short_name}/trustee/{trustee_name}/step-2", status_code=200)
async def get_trustee_step_2(
    election_short_name: str, trustee_name: str, session=Depends(get_session)
):
    """
    GET step 2 of the keygenerator trustee
    """
    # make sure that the election is in step 2
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    if election.global_keygen_step != 2:
        return {"message": "The election is not in step 2"}

    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )

    key_gen_shares = crud.read_keygen_shares_by_receiver_and_election_short_name(
        session=session,
        receiver=trustee.participant_id,
        election_short_name=election_short_name,
    )
    # sort keygen shares by sender
    key_gen_shares = sorted(key_gen_shares, key=lambda k: k.sender)

    return {
        "signed_encrypted_shares": [
            json.loads(key_gen_share.share) for key_gen_share in key_gen_shares
        ],
        "signed_broadcasts": [
            json.loads(trustee.signed_broadcasts)
            for trustee in sorted(election.trustees, key=lambda t: t.participant_id)
        ],
    }


@api_router.post(
    "/{election_short_name}/trustee/{trustee_name}/step-2", status_code=200
)
async def post_trustee_step_2(
    election_short_name: str,
    trustee_name: str,
    trustee_data: schemas.KeyGenStep2Data,
    session=Depends(get_session),
):
    """
    POST step 2 of the keygenerator trustee
    """
    # make sure that the election is in step 2
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    if election.global_keygen_step != 2:
        return {"message": "The election is not in step 2"}

    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )

    # verify the acknowledgements
    for ack in trustee_data.acknowledgements:
        # TODO: ack implement verification
        isValid = True  # verify_ack(ack)
        if not isValid:
            return {"message": "The acknowledgement is not valid"}

    # save the trustees acknowledgements
    trustee = crud.update_trustee_by_uuid(
        session=session,
        uuid=trustee.uuid,
        fields={
            "local_keygen_step": 3,
            "acknowledgements": json.dumps(trustee_data.model_dump()),
        },
    )

    # if all trustees have uploaded their acknowledgements, update global keygen step
    if all(trustee.local_keygen_step == 3 for trustee in election.trustees):
        crud.update_election_by_short_name(
            session=session,
            short_name=election_short_name,
            fields={"global_keygen_step": 3},
        )

    return {"message": "Keygenerator step 2 completed successfully"}


# --- step 3 ---


@api_router.get("/{election_short_name}/trustee/{trustee_name}/step-3", status_code=200)
async def get_trustee_step_3(
    election_short_name: str, trustee_name: str, session=Depends(get_session)
):
    """
    GET step 3 of the keygenerator trustee
    """
    # make sure that the election is in step 2
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    if election.global_keygen_step != 3:
        return {"message": "The election is not in step 2"}

    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )

    crud.delete_keygen_shares_by_receiver_and_election_short_name(
        session=session,
        receiver=trustee.participant_id,
        election_short_name=election_short_name,
    )

    # compute any other parameters needed in future versions of the protocol
    return {} # currently returns an empty dictionary 


@api_router.post(
    "/{election_short_name}/trustee/{trustee_name}/step-3", status_code=200
)
async def post_trustee_step_3(
    election_short_name: str,
    trustee_name: str,
    trustee_data: schemas.KeyGenStep3Data,
    session=Depends(get_session),
):
    # make sure that the election is in step 3
    election = crud.read_election_by_short_name(
        session=session, short_name=election_short_name
    )
    if election.global_keygen_step != 3:
        return {"message": "The election is not in step 3"}

    trustee = crud.read_trustee_by_name_and_election_short_name(
        session=session,
        name=trustee_name,
        election_short_name=election_short_name,
    )

    # TODO: verify the verification key
    isValid = True
    if not isValid:
        return {"message": "The verification key is not valid"}

    # save the verification key
    trustee = crud.update_trustee_by_uuid(
        session=session,
        uuid=trustee.uuid,
        fields={
            "local_keygen_step": 4,
            "verification_key": trustee_data.verification_key,
        },
    )

    # if all trustees have uploaded their verification keys, update global keygen step
    if all(trustee.local_keygen_step == 4 for trustee in election.trustees):
        crud.update_election_by_short_name(
            session=session,
            short_name=election_short_name,
            fields={"global_keygen_step": 4},
        )

    return {"message": "Keygenerator step 3 completed successfully"}


@api_router.get(
    "/{short_name}/trustee/{trustee_name}/decrypt-and-prove", status_code=200
)
async def get_trustee_decrypt_and_prove(short_name: str, trustee_name: str):
    """
    Decrypt and prove
    """
    return json.load(fp=open("decrypt_and_prove.json", "r"))


@api_router.post(
    "/{short_name}/trustee/{trustee_name}/decrypt-and-prove", status_code=200
)
async def post_trustee_decrypt_and_prove(
    short_name: str, trustee_name: str, trustee_data: schemas.DecryptionIn
):
    """
    Decrypt and prove
    """
    return {"message": "The decryption was uploaded successfully"}


# --- Election ---
@api_router.post("/{short_name}/start-election", status_code=200)
async def start_election(short_name: str, session=Depends(get_session)):
    """
    Start the election
    """

    election = crud.read_election_by_short_name(session=session, short_name=short_name)
    if election.global_keygen_step != 4:
        return {"message": "Some trustees have not completed the key generation"}
    
    # Parse the first broadcast of each trustee into ECC.EccPoint objects
    curve = json.loads(election.crypto_params)["tdkg"]["curve"]
    get_first_broadcast = lambda t: {
        k: int(v) if k in ("x", "y") else v  # Convert x and y to ints, leave others as-is
        for k, v in json.loads(t.signed_broadcasts)[0]["broadcast"].items()
    }
    _trustees_first_broadcast = [
        ECC.EccPoint(curve=curve, **b)
        for b in [get_first_broadcast(t) for t in election.trustees]
    ]

    # The election public key is the sum of the first broadcasts
    _start, *_iterable = _trustees_first_broadcast
    election_public_key = sum(_iterable, start=_start)

    # Save election public key
    election = crud.update_election_by_short_name(
        session=session,
        short_name=short_name,
        fields={
            "public_key": json.dumps({
                "x": int(election_public_key.x),
                "y": int(election_public_key.y)
            })
        }
    )
