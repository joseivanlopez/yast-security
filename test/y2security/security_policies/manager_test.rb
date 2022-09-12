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
require "y2security/security_policies/manager"
require "y2security/security_policies/disa_stig_policy"

describe Y2Security::SecurityPolicies::Manager do
  before do
    allow(ENV).to receive(:[]) do |key|
      env[key]
    end

    allow(ENV).to receive(:keys).and_return env.keys
  end

  let(:env) { {} }

  let(:disa_stig_policy) { Y2Security::SecurityPolicies::DisaStigPolicy.new }
  let(:target_config) do
    instance_double(Y2Security::SecurityPolicies::TargetConfig)
  end

  describe ".new" do
    context "when YAST_SECURITY_POLICIES does not contain a policy" do
      let(:env) { { "YAST_SECURITY_POLICIES" => "" } }

      it "does not enable a policy" do
        expect(subject.enabled_policies).to be_empty
      end
    end

    context "when YAST_SECURITY_POLICIES contains an unknown policy" do
      let(:env) { { "YAST_SECURITY_POLICIES" => "DisaStig" } }

      it "does not enable a policy" do
        expect(subject.enabled_policies).to be_empty
      end
    end

    context "when YAST_SECURITY_POLICIES contains a known policy" do
      let(:env) { { "YAST_SECURITY_POLICIES" => "foo,Disa_Stig" } }

      it "enables the policy" do
        expect(subject.enabled_policies).to contain_exactly(disa_stig_policy)
      end
    end
  end

  describe "#policies" do
    it "returns all the known policies" do
      expect(subject.policies).to contain_exactly(disa_stig_policy)
    end
  end

  describe "#find_policy" do
    context "if there is a policy with the given id" do
      let(:id) { :disa_stig }

      it "returns the policy" do
        expect(subject.find_policy(id)).to eq(disa_stig_policy)
      end
    end

    context "if there is no policy with the given id" do
      let(:id) { :unknown }

      it "returns nil" do
        expect(subject.find_policy(id)).to be_nil
      end
    end
  end

  describe "#enable_policy" do
    context "if the given policy is unknown" do
      let(:policy) { Y2Security::SecurityPolicies::Policy.new(:unknown, "Unknown") }

      it "does not enable the policy" do
        subject.enable_policy(policy)

        expect(subject.enabled_policies).to_not include(policy)
      end
    end

    context "if the given policy is known" do
      let(:policy) { disa_stig_policy }

      it "enables the policy" do
        subject.enable_policy(policy)

        expect(subject.enabled_policies).to include(policy)
      end
    end
  end

  describe "#disable_policy" do
    before do
      subject.enable_policy(disa_stig_policy)
    end

    it "disables the given policy" do
      subject.disable_policy(disa_stig_policy)

      expect(subject.enabled_policies).to_not include(disa_stig_policy)
    end
  end

  describe "#enabled_policy?" do
    context "if the given policy is enabled" do
      before do
        subject.enable_policy(disa_stig_policy)
      end

      it "returns true" do
        expect(subject.enabled_policy?(disa_stig_policy)).to eq(true)
      end
    end

    context "if the given policy is not enabled" do
      before do
        subject.disable_policy(disa_stig_policy)
      end

      it "returns false" do
        expect(subject.enabled_policy?(disa_stig_policy)).to eq(false)
      end
    end
  end

  describe "#failing_rules" do
    context "if there are no enabled policies" do
      before do
        subject.disable_policy(disa_stig_policy)
      end

      it "returns an empty array" do
        expect(subject.failing_rules(target_config)).to be_empty
      end
    end

    context "if there are enabled policies" do
      let(:rule) { instance_double(Y2Security::SecurityPolicies::Rule) }

      before do
        subject.enable_policy(disa_stig_policy)

        allow(disa_stig_policy).to receive(:failing_rules)
          .with(target_config, include_disabled: true, scope: nil).and_return([rule])
      end

      it "returns a hash where the keys are the policies and the values the failing rules" do
        expect(subject.failing_rules(target_config)).to eq(disa_stig_policy => [rule])
      end

      context "when a scope is given" do
        it "only includes the rules for the given scope" do
          expect(disa_stig_policy).to receive(:failing_rules)
            .with(target_config, include_disabled: true, scope: :bootloader).and_return([rule])
          expect(subject.failing_rules(target_config, scope: :bootloader))
            .to eq(disa_stig_policy => [rule])
        end
      end

      context "when disabled rules must be excluded" do
        it "does not include disabled rules" do
          expect(disa_stig_policy).to receive(:failing_rules)
            .with(target_config, include_disabled: false, scope: nil).and_return([rule])
          expect(subject.failing_rules(target_config, include_disabled: false))
            .to eq(disa_stig_policy => [rule])
        end
      end
    end
  end
end
