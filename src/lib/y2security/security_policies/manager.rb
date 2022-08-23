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
require "y2security/security_policies/issue"

module Y2Security
  module SecurityPolicies
    class Manager
      include Singleton

      def initialize
        @enabled_policies = []

        enable_policies
      end

      # Returns the list of known security policies
      #
      # @return [Array<Policy>]
      def policies
        @policies ||= [DisaStigPolicy.new].freeze
      end

      # Returns the security policy with the given ID
      #
      # @param id [Symbol] Security policy ID
      def policy(id)
        policies.find { |p| p.id == id }
      end

      def enable_policy(id)
        return unless policy(id)

        @enabled_policies.push(id).uniq!
      end

      def disable_policy(id)
        @enabled_policies.delete(id)
      end

      def enabled_policy?(id)
        @enabled_policies.include?(id)
      end

      # Returns the enabled policies
      #
      # @return [Array<Policy>] List of enabled security policies
      def enabled_policies
        @enabled_policies.map { |id| policy(id) }
      end

      # @return [IssuesCollection]
      def issues(scope = nil)
        issues_collection = IssuesCollection.new

        enabled_policies.each do |policy|
          issues_collection.update(policy.id, policy.validate(scope))
        end

        issues_collection
      end

      private

      ENV_SECURITY_POLICIES = "YAST_SECURITY_POLICIES".freeze
      private_constant :ENV_SECURITY_POLICIES

      def enable_policies
        ids = policies_id_from_env
        ids.each { |id| enable_policy(id) }
      end

      def policies_id_from_env
        env_policies.map { |v| policy_id_from_env(v) }.compact.uniq
      end

      def policy_id_from_env(value)
        return DisaStigPolicy.new.id if value.match?(/\Adisa_stig\z/i)
      end

      def env_policies
        # Sort the keys to have a deterministic behavior and to prefer
        # all-uppercase over the other variants, then do a case insensitive
        # search
        key = ENV.keys.sort.find { |k| k.match(/\A#{ENV_SECURITY_POLICIES}\z/i) }
        return [] unless key

        ENV[key].split(",")
      end
    end
  end
end
