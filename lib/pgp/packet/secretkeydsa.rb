require 'pgp/packet/secretkey'
require 'pgp/packet/dsakeysupport'


module PGP
module Packet


class SecretKeyDSA < SecretKey
  include DSAKeySupport
end


end
end
