require 'pgp/packet/publicsubkey'
require 'pgp/packet/elgamalkeysupport'


module PGP
module Packet


class PublicSubkeyElgamal < PublicSubkey
  include ElgamalKeySupport
end


end
end
