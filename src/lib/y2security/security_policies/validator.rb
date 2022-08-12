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

module Y2Security
  module SecurityPolicies
    # Base class for security policies validators
    class Validator
      include Yast::I18n
      include Yast::Logger

      class << self
        # Returns a validator for the given policy
        #
        # @param policy [SecurityPolicy] Security policy to build the validator for
        def for(policy)
          require "y2security/security_policies/#{policy.id}_validator"
          klass_prefix = policy.id.to_s.split("_").map(&:capitalize).join
          klass = Y2Security::SecurityPolicies.const_get("#{klass_prefix}Validator")
          klass.new
        rescue LoadError, NameError => e
          log.info "Could not load a validator for #{policy}: #{e.message}"
        end
      end

      def initialize
        textdomain "security"
      end

      # Returns the issues found for the given scope
      #
      # @param _scopes [Symbol] Scopes to validate (:network, :storage, :bootloader, etc.)
      #   If not scopes are given, it runs through all of them.
      def validate(*_scopes); end
    end
  end
end