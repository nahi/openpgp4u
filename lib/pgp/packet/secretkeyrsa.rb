require 'pgp/packet/secretkey'
require 'pgp/packet/rsakeysupport'


module PGP
module Packet


class SecretKeyRSA < SecretKey
  include RSAKeySupport
end


end
end
