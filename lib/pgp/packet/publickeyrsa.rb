require 'pgp/packet/publickey'
require 'pgp/packet/rsakeysupport'


module PGP
module Packet


class PublicKeyRSA < PublicKey
  include RSAKeySupport
end


end
end
