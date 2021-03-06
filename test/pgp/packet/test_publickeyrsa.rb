require 'test/unit'
require 'pgp/packet'


module TestPGP
module TestPacket


class TestPublicKeyRSA < Test::Unit::TestCase
  include PGP

  def setup
    @pgp_asc_pub = <<__EOP__
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBEFmdNIBCADRlQgRryBHAjaI8EspHxNngzGBS3jj3tWYO52xMGRDKHZLPWwF
vsIdjaWu9e/qTrjNeGklytthHRcG1v5GUSSFSSFZnDFsN1ycuBYgi0A+xIRL3WBs
3PBIZIxgbm8oCBjbHJK5E0s8h1WYEU7bE798YgL0Z5CAVTgMkACZE1XursUw9OQ9
XK6BNBiYiQmrVYNV79CMpHdnpc3/N+UEQaL+i5bMYXkcp7dMgoZgn75WHgYGV1rJ
dk0Mi3RBBE73uiR981QqZyP6ONi1jCWeLS4iei8Iut/NzcinhXWMoKVhx5wik6pW
PMr22QTwUoATJFChhhBYw73wWPokrlaQ89yBABEBAAG0I05BS0FNVVJBLCBIaXJv
c2hpIDxjaWNAZXhhbXBsZS5vcmc+iQEuBBABAgAYBQJBZnTTAgsCAhkBBRsDAAAA
BR4BAAAAAAoJEPATknA6gGSQl48H/iP/YchrSP9N1pm+WujHJWAqSkq4Wv4RXS5c
ukeyPBbZTTtP7DZii+RIvH5Ch2IpPHVUiHWNOT4Iir8sV7nOlR62Bfn48KNOv744
bhRgALe9thnmqKD5qX9lL5vWKLCu/GE0lFHxwvBPvPIHGmcZ/Ge3ZjQbEvhuydmW
r6FQSM76qkl6kj6Pb6WrUDw0MEUURC7l3jiSNiEGBC+Q+ReqybsCcJqX/rfFpmAQ
DIRLr27+dgYj86DYyabG/b+ZHCZot6EadNbdFhiMUNjwVoeqj9Tat2bvu2rpl/04
A0M7fXv0EIkNLwCQSCC3sFpH5WM1CAKEek+KVatGemi3eCoJkkO5AQ0EQWZ01AEI
ALSn08nLi8pZdzDPSw74zpF2wwzMYl870PZrCIbGDz8q4ffqoWR/67WqxgGGDQD+
T4QP2LEdW7woQiEY4Rtn05RPcNitjQFqT2mVVYzYcFb+cR+nkUMRAhJt0UdeyU8q
0v8fimoxfHSW37J3C310ca0ULVfnCcfTSdhIgUtXrjNfZId36MRBe3QUyI7GScAu
eq7q7kZl3dQubNlKYvtt/NVoyandNN952oXzibmIuKzdprfImbIv3F677TGa9y6H
Pm91vjn7wjEJEiD6TbCrxd8RojlMzGZLoD9QVRwskrWyzWE8suAbCbFvatfUcm15
N4P6qPsBKV/zbhe5iJL10qsAEQEAAYkBIgQYAQIADAUCQWZ01AUbDAAAAAAKCRDw
E5JwOoBkkO9dB/9rv5Dpb6r8b5Wgb7Rv29AuN8p180lsI9s8WWaaUuPDJcJc3lN6
fmnUUmo+/0E8SMjzY4AQ38I9g1jh/ZjBPk2Vj1KG7lMfAHCqiqDXxFgrcZchiZlP
ykUk5kQwXkHzazbnsFxDQOJn5xutmLb9W4aNpvyfo/13TogMQVMX6JXYPnMXDn0Z
BhrcsRXmyr3HuNtdPdPFIGrH3PZHsACzmRmtrl+dtMXpOHi/5wudgyNNM6cwEePj
G5ZIF7UuvfEDPnonkgqarrjmv00v344c/B8ai6P5AP0BeAiGjylLiymsjey6jCdm
UIWur7ty3zA3NlYsB3xg+ebhIQynFGIdYmTh
=vxBn
-----END PGP PUBLIC KEY BLOCK-----
__EOP__

    @pgp_asc_sec = <<__EOP__
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
YRm2grhKW2tiP/4=
=CaT2
-----END PGP PRIVATE KEY BLOCK-----
__EOP__
  end

  def test_parse
    # parse
    result = Packet::Packet.load(Armor.new(@pgp_asc_pub).body)
    assert_equal(5, result.size)
    pubkey, pubuserid, pubusig, pubsubkey, pubsubsig = result
    result = Packet::Packet.load(Armor.new(@pgp_asc_sec).body)
    assert_equal(3, result.size)
    seckey, secuserid, secsubkey = result
    # re-build
    pubusig.secretkey = seckey
    pubusig.target = pubkey.dump + [0xb4].pack("c") + [pubuserid.userid.length].pack("N") + pubuserid.userid
    pubsubsig.secretkey = seckey
    pubsubsig.target = pubkey.dump + pubsubkey.as_primarykey.dump
    rebuildsrc = [pubkey, pubuserid, pubusig, pubsubkey, pubsubsig].collect { |packet| packet.dump }.join

    # new-build
    newusig = Packet::Packet.load(pubusig.dump)[0]
    newusig.secretkey = seckey
    newusig.target = pubkey.dump + [0xb4].pack("c") + [pubuserid.userid.length].pack("N") + pubuserid.userid
    newsubsig = Packet::Packet.load(pubsubsig.dump)[0]
    newsubsig.secretkey = seckey
    newsubsig.target = pubkey.dump + pubsubkey.as_primarykey.dump
    newbuildsrc = [pubkey, pubuserid, newusig, pubsubkey, newsubsig].collect { |packet| packet.dump }.join

    # re-build == new-build
    assert_equal(rebuildsrc, newbuildsrc)

    # cycle test
    a = Armor.new; a.body = rebuildsrc
    a.type = :PUBLIC_KEY_BLOCK
    assert_equal(@pgp_asc_pub, a.dump)

    b = Armor.new; b.body = newbuildsrc
    b.type = :PUBLIC_KEY_BLOCK
    assert_equal(@pgp_asc_pub, b.dump)
  end
end


end
end
