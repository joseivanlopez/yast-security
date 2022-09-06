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

require "y2security/security_policies/storage_rule"

module Y2Security
  module SecurityPolicies
    class MissingMountPoint < StorageRule
      attr_reader :mount_point

      def initialize(id, mount_point)
        @mount_point = mount_point
        super(id, "description")
      end

      def validate(devicegraph = nil)
        devicegraph ||= default_devicegraph

        paths = devicegraph.mount_points.map(&:path)
        paths.include?(mount_point)
      end
    end
  end
end
