require 'cfn-nag/violation'
require_relative 'base'

class CloudFormationAuthenticationRule < BaseRule
  def rule_text
    'Specifying credentials in the template itself is probably not the safest thing'
  end

  def rule_type
    Violation::WARNING
  end

  def rule_id
    'W1'
  end

  def audit_impl(cfn_model)
    violating_auth = cfn_model.resources_by_type('AWS::CloudFormation::Authentication').select do |auth|
      auth.accessKeyId.nil? && auth.password.nil? && auth.secretKey.nil?
    end

    violating_auth.map { |auth| violating_user.logical_resource_id }
  end

end
