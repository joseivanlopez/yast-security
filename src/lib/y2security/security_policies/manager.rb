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

require "singleton"
require "y2security/security_policies/disa_stig_policy"
require "y2security/security_policies/issues"

module Y2Security
  module SecurityPolicies
    class Manager
      include Singleton

      # Returns the list of known security policies
      #
      # @return [Array<Policy>]
      def policies
        @policies ||= [DisaStigPolicy.new]
      end

      # Returns the security policy with the given ID
      #
      # @param id [Symbol] Security policy ID
      def policy(id)
        policies.find { |p| p.id == id }
      end

      # Returns the enabled policies
      #
      # @return [Array<Policy>] List of enabled security policies
      def enabled_policies
        policies.select(&:enabled?)
      end

      # @return [IssuesCollection]
      def issues(*scopes)
        issues_collection = IssuesCollection.new

        enabled_policies.each do |policy|
          issues_collection.update(policy, policy.validate(*scopes))
        end

        issues_collection
      end
    end
  end
end
