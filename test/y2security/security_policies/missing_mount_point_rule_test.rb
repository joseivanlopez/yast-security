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

require_relative "../../test_helper"
require "y2security/security_policies/missing_mount_point_rule"

describe Y2Security::SecurityPolicies::MissingMountPointRule do
  subject { described_class.new("SLES-15-040200", "/home") }

  describe "#id" do
    it "returns the rule ID" do
      expect(subject.id).to eq("SLES-15-040200")
    end
  end

  describe "#validate" do
    let(:devicegraph) { Y2Storage::StorageManager.instance.staging }

    context "when the given mount point is missing" do
      before do
        fake_storage_scenario("plain.yml")
      end

      it "returns an issue for missing mount point" do
        issue = subject.validate(devicegraph)

        expect(issue.message)
          .to match(/must be a separate mount point for \/home/)
        expect(issue.scope).to eq(:storage)
      end
    end

    context "when the given mount point /home is not missing" do
      before do
        fake_storage_scenario("plain.yml")

        sda1 = devicegraph.find_by_name("/dev/sda1")
        sda1.mount_point.path = "/home"

        sda3 = devicegraph.find_by_name("/dev/sda3")
        sda3.mount_point.path = "/var"
      end

      it "does not return an issue for missing mount points" do
        issue = subject.validate(devicegraph)
        expect(issue).to be_nil
      end
    end
  end
end
