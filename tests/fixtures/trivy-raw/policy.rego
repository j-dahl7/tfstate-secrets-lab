# METADATA
# title: Raw Terraform fixture detects state-persisted secret arguments
# description: Configuration wiring fixture, not the production secure-example policy.
# schemas:
# - input: schema["terraform-raw"]
# custom:
#   id: NLSCFG001
#   avd_id: AVD-NLS-0001
#   severity: HIGH
#   input:
#     selector:
#     - type: terraform-raw
package user.nlscfg001

import rego.v1

deny contains res if {
    some block in input.modules[_].blocks
    block.kind == "resource"
    block.type == "aws_secretsmanager_secret_version"
    "secret_string" in object.keys(block.attributes)
    res := result.new("Synthetic fixture uses a state-persisted secret argument", block)
}
