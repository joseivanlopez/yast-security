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

require "yast"
require "y2security/security_policies/rule"

Yast.import "Lan"

module Y2Security
  module SecurityPolicies
    class NetworkRule < Rule
      def validate(config = nil)
        true
      end

      def fix(config = nil)
        nil
      end

      private

      # Default network config to use
      #
      # @return [Y2Network::Config]
      def default_config
        Yast::Lan.yast_config
      end
    end
  end
end
