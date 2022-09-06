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

require "y2security/security_policies/scopes"

module Y2Security
  module SecurityPolicies
    # Base class for security policies
    class Policy
      # Id of the policiy
      #
      # @return [Symbol]
      attr_reader :id

      # Name of the policy
      #
      # @return [String]
      attr_reader :name

      # Packages to install for the policy
      #
      # @return [Array<String>]
      attr_reader :packages

      # @param id [Symbol]
      # @param name [String]
      # @param packages [Array<String>]
      def initialize(id, name, packages = [])
        @id = id
        @name = name
        @packages = packages
      end

      # Compares two policies
      #
      # @param other [Policy]
      # @return [Boolean]
      def ==(other)
        other.class == self.class && other.id == id
      end

      alias_method :eql?, :==

      # Whether the given value matches with the id of the policy
      #
      # @param value [#to_sym]
      # @return [Boolean]
      def is?(value)
        id == value.to_sym
      end

      def rules
        []
      end

      def failing_rules
        rules.reject(&:validate)
      end

      def failing_storage_rules(devicegraph = nil)
        storage_rules = rules.select { |r| r.is_a?(StorageRule) }

        storage_rules.reject { |r| r.validate(devicegraph) }
      end

      def failing_network_rules(config = nil)
        network_rules = rules.select { |r| r.is_a?(NetworkRule) }

        network_rules.reject { |r| r.validate(config) }
      end
    end
  end
end
