require 'pgp/packet/publickey'
require 'pgp/packet/dsakeysupport'


module PGP
module Packet


class PublicKeyDSA < PublicKey
  include DSAKeySupport
end


end
end
