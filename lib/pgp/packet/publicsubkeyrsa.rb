require 'pgp/packet/publicsubkey'
require 'pgp/packet/rsakeysupport'


module PGP
module Packet


class PublicSubkeyRSA < PublicSubkey
  include RSAKeySupport
end


end
end
