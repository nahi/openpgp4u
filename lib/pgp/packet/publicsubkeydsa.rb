require 'pgp/packet/publicsubkey'
require 'pgp/packet/dsakeysupport'


module PGP
module Packet


class PublicSubkeyDSA < PublicSubkey
  include DSAKeySupport
end


end
end
