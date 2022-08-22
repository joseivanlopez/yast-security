# Copyright (c) [2022] SUSE LLC
#
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, contact SUSE LLC.
#
# To contact SUSE LLC about this file by physical or electronic mail, you may
# find current contact information at www.suse.com.

require "y2security/security_policies/scope"

module Y2Security
  module SecurityPolicies
    class Scope
      class << self
        def all
          [network, storage, firewall, bootloader]
        end

        def network
          new(:network)
        end

        def storage
          new(:storage)
        end

        def firewall
          new(:firewall)
        end

        def bootloader
          new(:bootloader)
        end
      end

      attr_reader :id

      def ==(other)
        id == other.id
      end

      private

      def initialize(id)
        @id = id
      end
    end
  end
end
