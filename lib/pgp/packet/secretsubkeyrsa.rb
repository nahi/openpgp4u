require 'pgp/packet/secretsubkey'
require 'pgp/packet/rsakeysupport'


module PGP
module Packet


class SecretSubkeyRSA < SecretSubkey
  include RSAKeySupport
end


end
end
