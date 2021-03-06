require 'test/unit'
require 'pgp/packet'
require 'pgp/mpi'
require 'pgp/hexdump'


module TestPGP
module TestPacket


class TestSignature < Test::Unit::TestCase
  include PGP
  include PGP::Packet::SigSubPacket
  require File.join(File.expand_path(File.dirname(__FILE__)), 'testbase')
  include TestPGP::TestPacket::TestBase

  def setup
    firstpacket = "08 00 d1 95 08 11 af 20 47 02 36 88 f0 4b 29 1f 13 67 83 31 81 4b 78 e3 de d5 98 3b 9d b1 30 64 43 28 76 4b 3d 6c 05 be c2 1d 8d a5 ae f5 ef ea 4e b8 cd 78 69 25 ca db 61 1d 17 06 d6 fe 46 51 24 85 49 21 59 9c 31 6c 37 5c 9c b8 16 20 8b 40 3e c4 84 4b dd 60 6c dc f0 48 64 8c 60 6e 6f 28 08 18 db 1c 92 b9 13 4b 3c 87 55 98 11 4e db 13 bf 7c 62 02 f4 67 90 80 55 38 0c 90 00 99 13 55 ee ae c5 30 f4 e4 3d 5c ae 81 34 18 98 89 09 ab 55 83 55 ef d0 8c a4 77 67 a5 cd ff 37 e5 04 41 a2 fe 8b 96 cc 61 79 1c a7 b7 4c 82 86 60 9f be 56 1e 06 06 57 5a c9 76 4d 0c 8b 74 41 04 4e f7 ba 24 7d f3 54 2a 67 23 fa 38 d8 b5 8c 25 9e 2d 2e 22 7a 2f 08 ba df cd cd c8 a7 85 75 8c a0 a5 61 c7 9c 22 93 aa 56 3c ca f6 d9 04 f0 52 80 13 24 50 a1 86 10 58 c3 bd f0 58 fa 24 ae 56 90 f3 dc 81 00 11 01 00 01"

    fourthpacket = "08 00 b4 a7 d3 c9 cb 8b ca 59 77 30 cf 4b 0e f8 ce 91 76 c3 0c cc 62 5f 3b d0 f6 6b 08 86 c6 0f 3f 2a e1 f7 ea a1 64 7f eb b5 aa c6 01 86 0d 00 fe 4f 84 0f d8 b1 1d 5b bc 28 42 21 18 e1 1b 67 d3 94 4f 70 d8 ad 8d 01 6a 4f 69 95 55 8c d8 70 56 fe 71 1f a7 91 43 11 02 12 6d d1 47 5e c9 4f 2a d2 ff 1f 8a 6a 31 7c 74 96 df b2 77 0b 7d 74 71 ad 14 2d 57 e7 09 c7 d3 49 d8 48 81 4b 57 ae 33 5f 64 87 77 e8 c4 41 7b 74 14 c8 8e c6 49 c0 2e 7a ae ea ee 46 65 dd d4 2e 6c d9 4a 62 fb 6d fc d5 68 c9 a9 dd 34 df 79 da 85 f3 89 b9 88 b8 ac dd a6 b7 c8 99 b2 2f dc 5e bb ed 31 9a f7 2e 87 3e 6f 75 be 39 fb c2 31 09 12 20 fa 4d b0 ab c5 df 11 a2 39 4c cc 66 4b a0 3f 50 55 1c 2c 92 b5 b2 cd 61 3c b2 e0 1b 09 b1 6f 6a d7 d4 72 6d 79 37 83 fa a8 fb 01 29 5f f3 6e 17 b9 88 92 f5 d2 ab 00 11 01 00 01" 

    @mainkey = keypacket(firstpacket, 0x416674d2)
    @subkey = keypacket(fourthpacket, 0x416674d4)
  end

  def keypacket(str, created)
    bytes = str.gsub(/([0-9a-f]{2})\s*/) { [$1].pack("H*") }
    n = PGP::MPI.decode(bytes)
    e = PGP::MPI.decode(bytes[258..-1])
    packet = PGP::Packet::PublicKeyRSA.new(1)
    packet.n = n
    packet.e = e
    packet.keycreated = created
    packet
  end

  def test_pub_signature
    name = "NAKAMURA, Hiroshi <cic@example.org>"
    d = PGP::Packet::Signature.new(0x10, 1, 2)
    d.hashedsubpacket << CreationTime.new(0x416674d3)
    algo = PreferredSkeyAlgorithm.new
    algo.algorithm << 2
    d.hashedsubpacket << algo
    d.hashedsubpacket << PrimaryUserID.new(true)
    d.hashedsubpacket << KeyFlags.new(0x03)
    d.hashedsubpacket << Features.new(0x01)
    d.unhashedsubpacket << IssuerKeyID.new([0xf0, 0x13, 0x92, 0x70, 0x3a, 0x80, 0x64, 0x90].pack("c*"))
    d.target = @mainkey.dump + [0xb4].pack("C") + [name.length].pack("N") + name
    d.secretkey = SEC_KEY
    begin
      targetback = PUB_USIG.target
      secretkeyback = PUB_USIG.secretkey
      PUB_USIG.target = @mainkey.dump + [0xb4].pack("C") + [name.length].pack("N") + name
      PUB_USIG.secretkey = SEC_KEY
      assert_equal(PUB_USIG.dump, d.dump)
    ensure
      PUB_USIG.target = targetback
      PUB_USIG.secretkey = secretkeyback
    end
  end

  def test_pubsub_signature
    d = PGP::Packet::Signature.new(0x18, 1, 2)
    d.hashedsubpacket << CreationTime.new(0x416674d4)
    d.hashedsubpacket << KeyFlags.new(0x0c)
    d.unhashedsubpacket << IssuerKeyID.new([0xf0, 0x13, 0x92, 0x70, 0x3a, 0x80, 0x64, 0x90].pack("c*"))
    d.target = @mainkey.dump + @subkey.dump
    d.secretkey = SEC_KEY
    begin
      targetback = PUB_SUBSIG.target
      secretkeyback = PUB_SUBSIG.secretkey
      PUB_SUBSIG.target = @mainkey.dump + @subkey.dump
      PUB_SUBSIG.secretkey = SEC_KEY
      assert_equal(PUB_SUBSIG.dump, d.dump)
    ensure
      PUB_SUBSIG.target = targetback
      PUB_SUBSIG.secretkey = secretkeyback
    end
  end
end


end
end
