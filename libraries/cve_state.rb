# Three-state result for a CVE check.
#
#   describe cve_state(:mitigated, 'HTTP/2 disabled') do
#     it { should be_safe }
#   end
#
# States:
#   :patched   - a fixed version is deployed            -> passes
#   :mitigated - feature unused/off or workaround active -> passes
#   :vuln      - affected and nothing in place          -> fails
#   :unknown   - the check could not read what it needs  -> fails (never assume safe)
#
# The state is the first word of the test description, so scan.sh can read it
# back from the JSON report.
class CveState < Inspec.resource(1)
  name 'cve_state'
  desc 'Result of a CVE check: patched, mitigated, vuln or unknown'

  STATES = %i[patched mitigated vuln unknown].freeze

  def initialize(state, reason)
    raise ArgumentError, "unknown state #{state.inspect}" unless STATES.include?(state)

    @state = state
    @reason = reason
  end

  attr_reader :state, :reason

  def safe?
    %i[patched mitigated].include?(@state)
  end

  def to_s
    "#{@state.to_s.upcase}: #{@reason}"
  end
end

module VersionCheck
  # True if +version+ is at least the fixed release for its branch.
  #
  #   VersionCheck.patched?('8.4.28', '8.4' => '8.4.28', '8.3' => '8.3.37')  # => true
  #
  # A branch missing from +fixed+ (end of life, or no fix released yet)
  # counts as not patched.
  def self.patched?(version, fixed)
    branch = version.to_s[/\A\d+\.\d+/]
    min = fixed[branch]
    return false if min.nil?

    Gem::Version.new(version) >= Gem::Version.new(min)
  rescue ArgumentError
    false
  end
end
