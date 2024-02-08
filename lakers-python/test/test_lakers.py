import lakers
import pytest

# values from draft-ietf-lake-traces
CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
I = bytes.fromhex("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b")
R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
CONTEXT = [0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc, 0xea]

def test_gen_keys():
    priv, pub = lakers.p256_generate_key_pair()
    assert len(priv) == 32
    assert len(pub) == 32

def test_initiator():
    initiator = lakers.EdhocInitiator()
    message_1 = initiator.prepare_message_1(c_i=None, ead_1=None)
    assert type(message_1) == bytes

def test_responder():
    responder = lakers.EdhocResponder(R, CRED_R)

def test_handshake():
    initiator = lakers.EdhocInitiator()
    responder = lakers.EdhocResponder(R, CRED_R)

    # initiator
    message_1 = initiator.prepare_message_1(c_i=None, ead_1=None)

    # responder
    ead_1 = responder.process_message_1(message_1)
    assert ead_1 == None
    message_2 = responder.prepare_message_2(lakers.CredentialTransfer.ByReference, None, ead_1)
    assert type(message_2) == bytes

    # initiator
    c_r, id_cred_r, ead_2 = initiator.parse_message_2(message_2)
    assert ead_2 == None
    valid_cred_r = lakers.credential_check_or_fetch(id_cred_r, CRED_R)
    initiator.verify_message_2(I, CRED_I, valid_cred_r)
    message_3, i_prk_out = initiator.prepare_message_3(lakers.CredentialTransfer.ByReference, None)
    assert type(message_3) == bytes

    # responder
    id_cred_i, ead_3 = responder.parse_message_3(message_3)
    assert ead_3 == None
    valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
    r_prk_out = responder.verify_message_3(valid_cred_i)

    assert i_prk_out == r_prk_out

    i_oscore_secret = initiator.edhoc_exporter(0, [], 16)
    i_oscore_salt = initiator.edhoc_exporter(1, [], 8)
    r_oscore_secret = responder.edhoc_exporter(0, [], 16)
    r_oscore_salt = responder.edhoc_exporter(1, [], 8)
    assert i_oscore_secret == r_oscore_secret
    assert i_oscore_salt == r_oscore_salt

    # test key update with context from draft-ietf-lake-traces
    i_prk_out_new = initiator.edhoc_key_update(CONTEXT)
    r_prk_out_new = responder.edhoc_key_update(CONTEXT)
    assert i_prk_out_new == r_prk_out_new

def test_error():
    responder = lakers.EdhocResponder(R, CRED_R)
    with pytest.raises(ValueError) as err:
        _ead_1 = responder.process_message_1([1, 2, 3])
    assert str(err.value) == "EDHOCError::ParsingError"
