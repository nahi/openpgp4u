require 'pgp/packet/publickeyencryptedsessionkey'
require 'pgp/packet/rsakeysupport'


module PGP
module Packet


class PublicKeyEncryptedSessionKeyRSA < PublicKeyEncryptedSessionKey
  include RSAKeySupport
end


end
end
