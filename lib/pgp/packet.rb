require 'pgp/packet/packet'

require 'pgp/packet/publickeyencryptedsessionkeyrsa'    # Tag 1
require 'pgp/packet/signature'                          # Tag 2
require 'pgp/packet/sigsubpacket'                       # (sub packet)
# Symmetric-Key Encrypted Session Key Packets (Tag 3)
# One-Pass Signature Packets (Tag 4)
require 'pgp/packet/secretkeyrsa'                       # Tag 5 (RSA)
require 'pgp/packet/secretkeydsa'                       #       (DSA)
require 'pgp/packet/secretkeyelgamal'                   #       (Elgamal)
require 'pgp/packet/publickeyrsa'                       # Tag 6 (RSA)
require 'pgp/packet/publickeydsa'                       #       (DSA)
require 'pgp/packet/publickeyelgamal'                   #       (Elgamal)
require 'pgp/packet/secretsubkeyrsa'                    # Tag 7 (RSA)
require 'pgp/packet/secretsubkeydsa'                    #       (DSA)
require 'pgp/packet/secretsubkeyelgamal'                #       (Elgamal)
require 'pgp/packet/compresseddata'                     # Tag 8
# Symmetrically Encrypted Data Packet (Tag 9)
require 'pgp/packet/marker'                             # Tag 10
require 'pgp/packet/literaldata'                        # Tag 11
require 'pgp/packet/trust'                              # Tag 12
require 'pgp/packet/userid'                             # Tag 13
require 'pgp/packet/publicsubkeyrsa'                    # Tag 14 (RSA)
require 'pgp/packet/publicsubkeydsa'                    #        (DSA)
require 'pgp/packet/publicsubkeyelgamal'                #        (Elgamal)
require 'pgp/packet/userattribute'                      # Tag 17
require 'pgp/packet/symencryptedintegrityprotecteddata' # Tag 18 and 19


module PGP


module Packet
  def self.load(port, verbose = false)
    PGP::Packet::Packet.load(port, verbose)
  end
end


end
