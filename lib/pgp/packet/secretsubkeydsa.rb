require 'pgp/packet/secretsubkey'
require 'pgp/packet/dsakeysupport'


module PGP
module Packet


class SecretSubkeyDSA < SecretSubkey
  include DSAKeySupport
end


end
end
