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

module Y2Security
  module SecurityPolicies
    # This class represents a security policy
    #
    # It offers an API to get the security policies and run validations.
    #
    # @example Get all known security policies
    #   Policy.all #=> [#<Y2Security::Policy...>]
    #   Policy.all.map(&:name) #=> ["Defense Information Systems Agency STIG"]
    #
    # @example Run DISA STIG networking validation
    #   policy = Policy.find(:disa_stig)
    #   policy.validate.map(&:to_message) #=> ["Wireless devices are not allowed"]
    class Policy
      def initialize
        @enabled = false
      end

      # Enables the policy
      def enable
        @enabled = true
      end

      # Disables the policy
      def disable
        @enabled = false
      end

      # Determines whether the policy is enabled or not
      #
      # @return [Boolean] true if it is enabled; false otherwise
      def enabled?
        @enabled
      end

      # Validates whether the current configuration matches the policy
      #
      # @return [Array<Issue>] List of validation issues
      def validate
        validator.validate
      end

      # @return [Symbol] Security policy ID
      abstract_method :id

      # @return [String] Security policy name
      abstract_method :name

      # @return [Array<String>] Security policy packages needed
      abstract_method :packages

    private

      # Returns the associated validator
      #
      # @return [Validator]
      abstract_method :validator
    end
  end
end
