require 'pgp/packet/secretkey'
require 'pgp/packet/elgamalkeysupport'


module PGP
module Packet


class SecretKeyElgamal < SecretKey
  include ElgamalKeySupport
end


end
end
