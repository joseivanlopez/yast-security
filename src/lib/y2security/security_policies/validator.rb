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

require "abstract_method"
require "y2issues/list"

module Y2Security
  module SecurityPolicies
    # Base class for security policies validators
    class Validator
      module Scopes
        BOOTLOADER = :bootloader.freeze
        FIREWALL = :firewall.freeze
        NETWORK = :network.freeze
        STORAGE = :storage.freeze

        def all
          [BOOTLOADER, FIREWALL, NETWORK, STORAGE]
        end
      end

      # Returns the issues found for the given scope
      #
      # @param _scopes [Array<Symbol>] Scopes to validate (:network, :storage, :bootloader, etc.)
      #   If not scopes are given, it runs through all of them.
      # @return [Y2Issues::List]
      def validate(*scopes)
        scopes = Scopes.all & scopes
        scopes = Scopes.all if scopes.none?

        issues = scopes.map { |s| send("#{s}_issues") }.flatten
        Y2Issues::List.new(issues)
      end

      abstract_method :bootloader_issues

      abstract_method :firewall_issues

      abstract_method :network_issues

      abstract_method :storage_issues
    end
  end
end
