import lakers
import pytest

# values from traces-zeroconf.ipynb
W = bytes.fromhex("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F")
KID_I = 0x2b
CRED_V = bytes.fromhex("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072")
EAD_1_VALUE = bytes.fromhex("58287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724dda9784962883c96ed01ff122c3")
MESSAGE_1_WITH_EAD = bytes.fromhex("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724dda9784962883c96ed01ff122c3")
VOUCHER_RESPONSE = bytes.fromhex("8258520382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370158287818636f61703a2f2f656e726f6c6c6d656e742e7365727665724dda9784962883c96ed01ff122c34948c783671337f75bd5")
EAD_2_VALUE = bytes.fromhex("48c783671337f75bd5")

def test_authenticator_and_server():
    authenticator = lakers.AuthzAutenticator()
    enrollment_server = lakers.AuthzEnrollmentServer(
            W,
            CRED_V,
            [KID_I],
    )

    ead_1 = lakers.EADItem(1, True, EAD_1_VALUE)
    loc_w, voucher_request = authenticator.process_ead_1(ead_1, MESSAGE_1_WITH_EAD)
    voucher_response = enrollment_server.handle_voucher_request(voucher_request)
    assert type(voucher_response) == bytes

    ead_2 = authenticator.prepare_ead_2(voucher_response)
    assert ead_2.label() == 1
    assert ead_2.is_critical() == True
    assert ead_2.value() == EAD_2_VALUE
