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
require "y2security/security_policies/unknown_rule"

describe Y2Security::SecurityPolicies::UnknownRule do
  subject { described_class.new("package_aide_installed") }

  describe "#name" do
    it "returns the rule name" do
      expect(subject.name).to eq("package_aide_installed")
    end
  end

  describe "#id" do
    it "returns nil" do
      expect(subject.id).to be_nil
    end
  end

  describe "#pass?" do
    it "returns true" do
      expect(subject.pass?(nil)).to eq(true)
    end
  end

  describe "#fixable?" do
    it "returns false" do
      expect(subject.fixable?).to eq(false)
    end
  end
end
