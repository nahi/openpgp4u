require 'pgp/packet/publickey'
require 'pgp/packet/elgamalkeysupport'


module PGP
module Packet


class PublicKeyElgamal < PublicKey
  include ElgamalKeySupport
end


end
end
