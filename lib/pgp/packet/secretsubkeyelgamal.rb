require 'pgp/packet/secretsubkey'
require 'pgp/packet/elgamalkeysupport'


module PGP
module Packet


class SecretSubkeyElgamal < SecretSubkey
  include ElgamalKeySupport
end


end
end
