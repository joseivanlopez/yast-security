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

require "y2security/security_policies/network_rule"

module Y2Security
  module SecurityPolicies
    class NoWirelessRule < NetworkRule
      def initialize
        super("SLES-XXX", :network)
      end

      def validate(config = nil)
        config ||= default_config

        return true if config.nil?

        find_wireless_connections(config).none?
      end

      def fix(config = nil)
        config ||= default_config

        find_wireless_connections(config).each do |conn|
          conn.startmode = Y2Network::Startmode.create("off")
          config.add_or_update_connection_config(conn)
        end
      end

    private

      # Returns wireless connections which are not disabled
      #
      # @return [Array<Y2Network::ConnectionConfig::Wireless]
      def find_wireless_connections(config)
        config.connections.select do |conn|
          conn.is_a?(Y2Network::ConnectionConfig::Wireless) &&
          conn.startmode&.name != "off"
        end
      end
    end
  end
end
