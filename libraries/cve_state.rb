# Result types for CVE rules.
#
# Cinc Auditor loads library files into a private namespace: plain Ruby
# modules defined here are not visible from controls. Everything rules use is
# therefore a custom resource (cve_eval, cve_state, version_check).
#
# States:
#   PATCHED             - a fixed version is deployed                 -> passes
#   MITIGATED           - feature unused/off or full workaround active -> passes
#   PARTIALLY_MITIGATED - a partial workaround is in place, but risk   -> fails
#                         remains until upgraded
#   VULN                - affected and nothing in place               -> fails
#   UNKNOWN             - the check could not read what it needs      -> fails (never assume safe)
#
# The state is the first word of the test description, so scan.sh can read it
# back from the JSON report.

# Version comparison shared by the resources in this file.
module VersionCompare
  module_function

  # "v22.1.0" -> "22.1.0", "go1.25.3" -> "1.25.3", "8u432" -> "8.0.432",
  # "1.9.16p2" -> "1.9.16.2"
  def normalize(version)
    v = version.to_s.strip.sub(/\A(v|go)/, '')
    v = v.sub(/\A(\d+)u(\d+)\z/, '\1.0.\2')
    v.sub(/p(\d+)\z/, '.\1')
  end

  # "1.25.3" -> "1.25"; "8.0.432" -> "8.0"
  def branch(version)
    normalize(version)[/\A\d+\.\d+/]
  end

  # Fixed release that applies to +version+: looked up by "major.minor"
  # ('1.29'), then by major ('22'), then :all. nil if the branch has none.
  def fixed_for(version, fixed)
    v = normalize(version)
    fixed[branch(v)] || fixed[v[/\A\d+/]] || fixed[:all]
  end

  # true if +version+ >= the fixed release of its branch in +fixed+
  #   { '1.29' => '1.29.4', '1.28' => '1.28.2' }  or  { '24' => '24.22.3' }
  # A key of :all applies to every branch (single fixed version).
  # Branches missing from +fixed+ (EOL, or no fix yet) count as not patched.
  # A branch that was never affected can be listed with its first release,
  # e.g. '22' => '22.0.0'.
  def patched?(version, fixed)
    v = normalize(version)
    min = fixed_for(v, fixed)
    return false if min.nil?

    Gem::Version.new(v) >= Gem::Version.new(normalize(min))
  rescue ArgumentError
    false
  end
end

# Evaluate a CVE from version(s), fixed releases and mitigations.
#
#   n = nginx_facts
#   describe cve_eval('nginx', n.version, FIXED,
#                     mitigated: { 'HTTP/2 disabled' => !n.http2? },
#                     unknown:   ('could not read config' unless n.conf_readable?),
#                     vuln:      'HTTP/2 enabled') do
#     it { should be_safe }
#   end
#
# versions:  a version string, or [[label, version], ...] for products found
#            several times (Go binaries, apps). All must be patched for PATCHED.
# fixed:     fixed release per branch, see VersionCompare.patched?. {} if no fix yet.
# Options:
#   mitigated:      { 'reason' => true/false } - any true -> MITIGATED
#   partial:        { 'reason' => true/false } - workarounds that reduce but don't
#                   remove the risk; any true (and no full mitigation) ->
#                   PARTIALLY_MITIGATED
#   unknown:        reason string -> UNKNOWN (only if not patched)
#   vuln:           detail for the VULN message (default: which version fixes it)
#   note:           appended to the VULN message, e.g. 'only if the app serves HTTP/2'
#                   for conditions that live in application code and can't be checked
#   introduced:     first affected release, a version or a per-branch hash like
#                   +fixed+; older versions count as PATCHED (not affected)
#   distro_patched: true/false/nil from os_facts.pkg_patched? - distro packages
#                   backport fixes without changing the upstream version, so
#                   this wins over the upstream comparison when not nil.
class CveEval < Inspec.resource(1)
  name 'cve_eval'
  desc 'Evaluate a CVE as patched, mitigated, vuln or unknown'

  attr_reader :state, :reason

  def initialize(product, versions, fixed, opts = {})
    list = versions.is_a?(Array) ? versions : [[nil, versions]]
    list = list.map { |l| l.is_a?(Array) ? l : [nil, l] }
    @state, @reason = evaluate(product, list, fixed || {}, opts)
  end

  def safe?
    %i[patched mitigated].include?(@state)
  end

  def to_s
    "#{@state.to_s.upcase}: #{@reason}"
  end

  private

  def evaluate(product, list, fixed, opts)
    if list.empty? || list.any? { |_, v| v.to_s.empty? }
      return [:unknown, "could not read #{product} version"]
    end

    desc = list.map { |label, v| [label, "#{product} #{v}"].compact.join(' ') }
    distro = opts[:distro_patched]
    return [:patched, "#{desc.join(', ')} (distro package fixed)"] if distro == true

    introduced = opts[:introduced]
    introduced = { all: introduced } if introduced.is_a?(String)
    not_affected = lambda do |v|
      first = introduced && VersionCompare.fixed_for(v, introduced)
      first && !VersionCompare.patched?(v, all: first)
    end
    unpatched = list.reject { |_, v| not_affected.call(v) || (distro.nil? && VersionCompare.patched?(v, fixed)) }
    if unpatched.empty?
      tail = list.all? { |_, v| not_affected.call(v) } ? ' (version predates the bug)' : ''
      return [:patched, desc.join(', ') + tail]
    end

    shown = unpatched.map { |label, v| [label, "#{product} #{v}"].compact.join(' ') }.join(', ')
    return [:unknown, "#{shown}, #{opts[:unknown]}"] if opts[:unknown]

    active = (opts[:mitigated] || {}).select { |_, on| on }.keys
    return [:mitigated, "#{shown}, #{active.join(', ')}"] if active.any?

    partial = (opts[:partial] || {}).select { |_, on| on }.keys
    if partial.any?
      missing = (opts[:partial] || {}).reject { |_, on| on }.keys
      rest = missing.empty? ? '' : "; not in place: #{missing.join(', ')}"
      return [:partially_mitigated, "#{shown}, #{partial.join(', ')}#{rest}; upgrade to remove the remaining risk"]
    end

    detail = opts[:vuln]
    detail ||= if distro == false then 'distro package older than the fixed one'
               elsif fixed.empty? then 'no fixed release yet'
               elsif unpatched.all? { |_, v| VersionCompare.fixed_for(v, fixed).nil? }
                 'no fix for this branch (end of life?)'
               else
                 "fixed in #{unpatched.map { |_, v| VersionCompare.fixed_for(v, fixed) }.compact.uniq.join(' / ')}"
               end
    detail = "#{detail}; #{opts[:note]}" if opts[:note]
    [:vuln, "#{shown}, #{detail}"]
  end
end

# Hand-made state, for rules that don't fit cve_eval.
#
#   describe cve_state(:mitigated, 'HTTP/2 disabled') do
#     it { should be_safe }
#   end
class CveState < Inspec.resource(1)
  name 'cve_state'
  desc 'Result of a CVE check: patched, mitigated, vuln or unknown'

  STATES = %i[patched mitigated partially_mitigated vuln unknown].freeze

  attr_reader :state, :reason

  def initialize(state, reason)
    raise ArgumentError, "unknown state #{state.inspect}" unless STATES.include?(state)

    @state = state
    @reason = reason
  end

  def safe?
    %i[patched mitigated].include?(@state)
  end

  def to_s
    "#{@state.to_s.upcase}: #{@reason}"
  end
end

# Is a version at least the fixed release for its branch?
#
#   version_check('8.4.28', '8.4' => '8.4.28').patched?  # => true
class VersionCheck < Inspec.resource(1)
  name 'version_check'
  desc 'Compare a version against the fixed release per branch'

  def initialize(version, fixed)
    @version = version
    @fixed = fixed
  end

  def patched?
    VersionCompare.patched?(@version, @fixed)
  end

  def to_s
    "version #{@version}"
  end
end

# Evaluate a Go standard-library CVE across all running Go binaries
# (go_facts.binaries). Each binary is judged on its own:
#   PATCHED   - built with a fixed Go release, and (if the CVE also lives in
#               golang.org/x/net and the binary uses x/net/http2 directly)
#               linked against a fixed x/net
#   MITIGATED - not patched, but every GODEBUG setting in +godebug+ is set
#               in the process environment (only covers the standard library,
#               never a vulnerable x/net/http2)
#   VULN      - anything else
# The worst binary decides the state; the detail names the binaries.
#
#   go_facts.by_container.each do |container, bins|
#     describe go_cve(bins, { '1.27' => '1.27.2', '1.26' => '1.26.9' },
#                     xnet_fixed: '0.60.0', godebug: ['http2server=0'], container: container) do
#       it { should be_safe }
#     end
#   end
#
# container: the result belongs to that container, not the host. The reason
# then starts with "[@<container id>] " so scan.sh can file it under the
# container's own group.
class GoCve < Inspec.resource(1)
  name 'go_cve'
  desc 'Evaluate a Go CVE across running Go binaries'

  MAX_LISTED = 8

  attr_reader :state, :reason

  def initialize(binaries, fixed, opts = {})
    @container = opts[:container]
    xnet_fixed = opts[:xnet_fixed]
    godebug = Array(opts[:godebug])
    groups = { patched: [], mitigated: [], vuln: [] }

    binaries.each do |b|
      go_ok = VersionCompare.patched?(b[:go], fixed)
      xnet_ok = xnet_fixed.nil? || !b[:xnet_http2] ||
                (!b[:xnet].nil? && VersionCompare.patched?(b[:xnet], all: xnet_fixed))
      set = b[:godebug].to_s.split(',').map(&:strip)
      group = if go_ok && xnet_ok then :patched
              elsif xnet_ok && !godebug.empty? && (godebug - set).empty? then :mitigated
              else :vuln
              end
      groups[group] << describe_binary(b, go_ok, xnet_ok)
    end

    @state, @reason =
      if binaries.empty? then [:unknown, 'no Go binaries found']
      elsif groups[:vuln].any?
        [:vuln, "#{list(groups[:vuln])}; fixed in Go #{fixed.values.join(' / ')}#{xnet_fixed ? " and x/net #{xnet_fixed}" : ''}"]
      elsif groups[:mitigated].any? then [:mitigated, "#{list(groups[:mitigated])}; GODEBUG #{godebug.join(',')}"]
      else [:patched, "#{list(groups[:patched])} on fixed Go versions"]
      end
  end

  def safe?
    %i[patched mitigated].include?(@state)
  end

  def to_s
    marker = @container ? "[@#{@container}] " : ''
    "#{@state.to_s.upcase}: #{marker}#{@reason}"
  end

  private

  def describe_binary(b, go_ok, xnet_ok)
    parts = []
    parts << "go#{b[:go]}" unless go_ok
    parts << "x/net #{b[:xnet] || '?'}" unless xnet_ok
    parts << "go#{b[:go]}" if parts.empty?
    "#{b[:label]} (#{parts.join(', ')})"
  end

  def list(items)
    items = items.uniq
    shown = items.first(MAX_LISTED).join(', ')
    items.size > MAX_LISTED ? "#{shown} and #{items.size - MAX_LISTED} more" : shown
  end
end
