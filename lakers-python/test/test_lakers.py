import lakers
import pytest

CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
I = bytes.fromhex("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b")
R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")


def test_gen_keys():
    priv, pub = lakers.p256_generate_key_pair()
    assert len(priv) == 32
    assert len(pub) == 32

def test_initiator():
    initiator = lakers.EdhocInitiator()
    # initiator, message_1 = initiator.prepare_message_1(c_i=None, ead_1=None)
    message_1 = initiator.prepare_message_1(c_i=None)
    print(f"message_1 (len = {len(message_1)}): {message_1}")

def test_responder():
    responder = lakers.EdhocResponder(R, CRED_R)

def test_handshake():
    initiator = lakers.EdhocInitiator()
    responder = lakers.EdhocResponder(R, CRED_R)
    message_1 = initiator.prepare_message_1(c_i=None)
    print(f"message_1 (len = {len(message_1)}): {message_1}")
    ead_1 = responder.process_message_1(message_1)
    print(f"ead_1: {ead_1}")
    message_2 = responder.prepare_message_2(lakers.CredentialTransfer.ByReference, None, ead_1)
    print(f"message_2 (len = {len(message_2)}): {message_2}")
