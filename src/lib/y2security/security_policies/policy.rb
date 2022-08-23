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
      # @return [Symbol] Security policy ID
      def id; end

      # @return [String] Security policy name
      def name; end

      # @return [Array<String>] Security policy packages needed
      def packages
        []
      end

      # Returns the issues found for the given scope
      #
      # @param scopes [Array<Scope>] Scopes to validate (:network, :storage, :bootloader, etc.)
      #   If not scopes are given, it runs through all of them.
      # @return [Array<Y2Issues::Issue>]
      def validate(scope = nil)
        scopes = scope ? [scope] : default_scopes

        scopes.map { |s| issues_for(s) }.flatten
      end

      private

      def default_scopes
        [
          Scopes::Storage.new,
          Scopes::Bootloader.new,
          Scopes::Network.new,
          Scopes::Firewall.new
        ]
      end

      def issues_for(scope)
        []
      end
    end
  end
end
