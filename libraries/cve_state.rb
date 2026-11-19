# Helpers for CVE rules. Cinc Auditor loads library files into a private
# namespace, so plain Ruby modules defined here are not visible from
# controls. Everything shared is therefore a custom resource.

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

# Is a version at least the fixed release for its branch?
#
#   version_check('8.4.28', '8.4' => '8.4.28', '8.3' => '8.3.37').patched?  # => true
#
# A branch missing from the list (end of life, or no fix released yet)
# counts as not patched.
class VersionCheck < Inspec.resource(1)
  name 'version_check'
  desc 'Compare a version against the fixed release per branch'

  def initialize(version, fixed)
    @version = version.to_s
    @fixed = fixed
  end

  def patched?
    min = @fixed[@version[/\A\d+\.\d+/]]
    return false if min.nil?

    Gem::Version.new(@version) >= Gem::Version.new(min)
  rescue ArgumentError
    false
  end

  def to_s
    "version #{@version}"
  end
end
