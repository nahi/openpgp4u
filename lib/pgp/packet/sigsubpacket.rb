# Copyright 2004  NAKAMURA, Hiroshi <nakahiro@sarion.co.jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require 'pgp/packet/sigsubpacket/creationtime'                  # Tag 2
require 'pgp/packet/sigsubpacket/expirationtime'                # Tag 3
require 'pgp/packet/sigsubpacket/revocable'                     # Tag 7
require 'pgp/packet/sigsubpacket/keyexpirationtime'             # Tag 9
require 'pgp/packet/sigsubpacket/preferredskeyalgorithm'        # Tag 11
require 'pgp/packet/sigsubpacket/issuerkeyid'                   # Tag 16
require 'pgp/packet/sigsubpacket/preferredhashalgorithm'        # Tag 21
require 'pgp/packet/sigsubpacket/preferredcompressionalgorithm' # Tag 22
require 'pgp/packet/sigsubpacket/keyserverpreferences'          # Tag 23
require 'pgp/packet/sigsubpacket/primaryuserid'                 # Tag 25
require 'pgp/packet/sigsubpacket/keyflags'                      # Tag 27
require 'pgp/packet/sigsubpacket/reasonforrevocation'           # Tag 29
require 'pgp/packet/sigsubpacket/features'                      # Tag 30
require 'pgp/packet/sigsubpacket/internal'                      # Tag 100-110
