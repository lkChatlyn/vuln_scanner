# Per-target facts, shared by all rules.
#
# Each *_facts resource reads everything it needs in ONE shell call, the first
# time a rule asks for it, and caches the result for the rest of the run. Cinc
# Auditor runs one process per target, so the cache never mixes targets. This
# keeps the cost per target flat no matter how many rules use the same product.
#
# If the product is not installed, the single call exits early and
# installed? is false.
#
# Cinc Auditor loads library files into a private namespace: helpers used
# across files must be resources, so FactsSupport is only used in this file.

module FactsSupport
  def self.included(base)
    base.singleton_class.send(:attr_accessor, :cache)
  end

  def to_s
    self.class.name.to_s.sub(/Facts\z/, ' facts')
  end

  private

  def sh(cmd)
    inspec.command(cmd).stdout.to_s
  end

  # Load once per process (= per target)
  def facts
    self.class.cache ||= read_facts
  end

  def sections(out)
    # Split "===NAME===\n" separated output into a hash
    parts = {}
    key = 'head'
    out.each_line do |line|
      if line =~ /\A===([A-Z_]+)===\s*\z/
        key = Regexp.last_match(1).downcase
      else
        (parts[key] ||= +'') << line
      end
    end
    parts
  end

  def strip_hash_comments(text)
    text.to_s.lines.map { |l| l.sub(/#.*$/, '') }.join
  end
end

# ---------------------------------------------------------------------------
# OS, packages, kernel
# ---------------------------------------------------------------------------
class OsFacts < Inspec.resource(1)
  name 'os_facts'
  desc 'Distribution, kernel and package versions'
  include FactsSupport

  def distro
    facts[:distro]
  end

  # Running kernel, upstream form, e.g. "6.12.48". Debian and Ubuntu report an
  # ABI number in uname -r (6.1.0-28-amd64), so the real version is taken from
  # uname -v (Debian) or /proc/version_signature (Ubuntu) when available.
  def kernel
    facts[:kernel]
  end

  # Running kernel compared against the distro's fixed kernel package, e.g.
  #   { 'debian-12' => ['6.1.190-1', '6.12.113-1~deb12u1'], 'ubuntu-24.04' => '6.8.0-149.149' }
  # Several entries per distro cover kernel flavours (backports, HWE); the one
  # on the running kernel's branch is used. nil if none applies.
  def kernel_patched?(fixed)
    running = kernel_pkg
    return nil if running.nil?

    branch = ->(v) { v.to_s[/\A\d+\.\d+/] }
    min = Array(fixed[distro]).find { |c| branch.call(c) == branch.call(running) }
    min && pkg_version_ge?(running, min)
  end

  # Running kernel as a distro package version, e.g. "6.1.119-1" (Debian)
  # or "6.8.0-48.48" (Ubuntu); nil if unknown
  def kernel_pkg
    facts[:kernel_pkg]
  end

  def module_loaded?(mod)
    facts[:modules].include?(mod.tr('-', '_'))
  end

  # Module cannot be loaded: "install <mod> /bin/false" (or /bin/true) in
  # modprobe.d, or module loading disabled entirely.
  def module_blocked?(mod)
    m = mod.tr('-', '_')
    return false if facts[:builtin].include?(m) # compiled in: cannot be blocked

    facts[:blocked].include?(m) || facts[:modules_disabled]
  end

  # Module cannot be used at all: not loaded and blocked
  def module_unavailable?(mod)
    !module_loaded?(mod) && module_blocked?(mod)
  end

  # Unprivileged user namespaces switched off (Debian/Ubuntu sysctl or the
  # generic limit). Blocks the unprivileged route of several kernel LPEs, but
  # not processes or containers that already hold CAP_NET_ADMIN.
  def userns_disabled?
    sysctl('kernel.unprivileged_userns_clone') == '0' || sysctl('user.max_user_namespaces') == '0'
  end

  # iptables-save and nft ruleset of the current network namespace
  def firewall_rules
    facts[:firewall] ||= sh('iptables-save 2>/dev/null; nft list ruleset 2>/dev/null')
  end

  def sysctl(key)
    facts[:sysctl][key] ||= sh("cat /proc/sys/#{key.tr('.', '/')} 2>/dev/null").strip
  end

  def pkg_version(pkg)
    (facts[:pkgs] ||= {})[pkg] ||= begin
      v = case facts[:pkg_tool]
          when 'dpkg' then sh(%(dpkg-query -W -f='${Version}' #{pkg} 2>/dev/null)).strip
          when 'apk'  then sh(%(apk info -v #{pkg} 2>/dev/null | head -n 1)).strip.sub(/\A#{Regexp.escape(pkg)}-/, '')
          when 'rpm'  then sh(%(rpm -q --qf '%{VERSION}-%{RELEASE}' #{pkg} 2>/dev/null)).strip
          else ''
          end
      v.include?('not installed') ? '' : v
    end
  end

  # Is +version+ >= +min+ by the distro's own version rules? nil if unknown.
  def pkg_version_ge?(version, min)
    return nil if version.to_s.empty? || min.to_s.empty?

    out = case facts[:pkg_tool]
          when 'dpkg' then sh(%(dpkg --compare-versions '#{version}' ge '#{min}' && echo yes || echo no))
          when 'apk'  then sh(%(apk version -t '#{version}' '#{min}')).strip.then { |r| r == '<' ? 'no' : 'yes' }
          else ''
          end.to_s.strip
    { 'yes' => true, 'no' => false }[out]
  end

  # Distro fixed-version lookup. +fixed+ is keyed by distro, e.g.
  #   { 'debian-12' => '2.4.62-1~deb12u3', 'ubuntu-24.04' => '2.4.58-1ubuntu8.6' }
  # Returns true / false, or nil when this distro or package isn't covered.
  #
  # Only used when the installed package is on the same upstream branch as the
  # distro's fixed package. A vendor package (e.g. nginx.org's own build in the
  # official nginx image, "1.30.5-1~trixie") is then compared upstream instead,
  # because a newer branch number says nothing about distro backports.
  def pkg_patched?(pkg, fixed)
    min = fixed[distro]
    installed = pkg_version(pkg)
    return nil if min.nil? || installed.empty?

    upstream_branch = ->(v) { v.to_s.sub(/\A\d+:/, '')[/\A\d+\.\d+/] }
    return nil unless upstream_branch.call(installed) == upstream_branch.call(min)

    pkg_version_ge?(installed, min)
  end

  private

  def read_facts
    out = sh(<<~'SH')
      cat /etc/os-release 2>/dev/null
      echo ===KERNEL===
      uname -r; uname -v; cat /proc/version_signature 2>/dev/null
      echo ===MODULES===
      cut -d' ' -f1 /proc/modules 2>/dev/null
      echo ===BLOCKED===
      grep -rhsE '^[[:space:]]*install[[:space:]]+[^[:space:]]+[[:space:]]+/(usr/)?bin/(false|true)' /etc/modprobe.d /lib/modprobe.d /usr/lib/modprobe.d 2>/dev/null
      echo ===MODDIS===
      cat /proc/sys/kernel/modules_disabled 2>/dev/null
      echo ===BUILTIN===
      sed 's|.*/||; s|\.ko$||' "/lib/modules/$(uname -r)/modules.builtin" 2>/dev/null
      echo ===TOOLS===
      for t in dpkg-query apk rpm; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done
    SH
    s = sections(out)

    os = s['head'].to_s.lines.each_with_object({}) do |l, h|
      k, v = l.strip.split('=', 2)
      h[k] = v.to_s.delete('"') if v
    end
    id = os['ID'].to_s
    ver = os['VERSION_ID'].to_s
    ver = ver.split('.').first if id == 'debian'
    ver = ver.split('.')[0, 2].join('.') if id == 'alpine'

    k = s['kernel'].to_s.lines.map(&:strip)
    all = k.join(' ')
    debian = all[/Debian (\d+\.\d+\.\d+-[^\s)]+)/, 1]
    ubuntu = all[/Ubuntu (\d+\.\d+\.\d+-\d+\.\d+)\S* (\d+\.\d+\.\d+)/, 1]
    ubuntu_upstream = all[/Ubuntu \S+ (\d+\.\d+\.\d+)/, 1]
    kernel_pkg = debian || ubuntu
    kernel = if debian then debian[/\A\d+\.\d+\.\d+/]
             elsif ubuntu_upstream then ubuntu_upstream
             else k.first.to_s[/\A\d+\.\d+(\.\d+)?/]
             end

    tools = s['tools'].to_s.split
    pkg_tool = if tools.include?('dpkg-query') then 'dpkg'
               elsif tools.include?('apk') then 'apk'
               elsif tools.include?('rpm') then 'rpm'
               end

    {
      distro: id.empty? ? nil : "#{id}-#{ver}",
      kernel: kernel,
      builtin: s['builtin'].to_s.split.map { |m| m.tr('-', '_') },
      kernel_pkg: kernel_pkg,
      modules: s['modules'].to_s.split,
      blocked: s['blocked'].to_s.lines.map { |l| l.split[1].to_s.tr('-', '_') },
      modules_disabled: s['moddis'].to_s.strip == '1',
      pkg_tool: pkg_tool,
      sysctl: {},
    }
  end
end

# ---------------------------------------------------------------------------
# Web servers
# ---------------------------------------------------------------------------
class NginxFacts < Inspec.resource(1)
  name 'nginx_facts'
  desc 'nginx version, build options and effective config'
  include FactsSupport

  def installed?
    !facts[:version].nil?
  end

  def version
    facts[:version]
  end

  # --with-xxx flags from nginx -V, e.g. built_with?('http_v3_module')
  # Start of a statement: line start or after { ; }
  S = '(?:^|[{;}])'.freeze

  def built_with?(flag)
    facts[:configure].include?("--with-#{flag}")
  end

  # Effective config (nginx -T) without comments
  def conf
    facts[:conf]
  end

  def conf_readable?
    !conf.strip.empty?
  end

  def directive?(regex)
    conf.match?(regex)
  end

  def http2?
    directive?(/#{S}\s*http2\s+on\s*;/) || directive?(/#{S}\s*listen\s[^;]*\bhttp2\b/)
  end

  def http3?
    directive?(/#{S}\s*listen\s[^;]*\bquic\b/)
  end

  def resolver?
    directive?(/#{S}\s*resolver\s/)
  end

  def mail?
    directive?(/#{S}\s*mail\s*\{/)
  end

  def aio?
    directive?(/#{S}\s*aio\s+(on|threads)/)
  end

  def ssi?
    directive?(/#{S}\s*ssi\s+on\s*;/)
  end

  def mirror?
    directive?(/#{S}\s*mirror\s+(?!off\s*;)\S/)
  end

  def proxy_pass?
    directive?(/#{S}\s*proxy_pass\s/)
  end

  # proxy_pass whose target contains a variable, e.g. proxy_pass http://$host;
  def proxy_pass_variable?
    directive?(/#{S}\s*proxy_pass\s+[^;]*\$/)
  end

  def ssl_listen?
    directive?(/#{S}\s*listen\s[^;]*\bssl\b/) || directive?(/#{S}\s*ssl\s+on\s*;/)
  end

  # TLS 1.3 explicitly off: ssl_protocols is set and never lists TLSv1.3
  # (the default includes TLSv1.3 on current versions)
  def tls13_disabled?
    protos = conf.scan(/#{S}\s*ssl_protocols\s+([^;]*);/).flatten
    !protos.empty? && protos.none? { |p| p.include?('TLSv1.3') }
  end

  # A map with regex keys (~ / ~*) and numbered captures ($1..$9) used in
  # root or log_format
  def regex_map_captures?
    directive?(/#{S}\s*map\s[^{]*\{[^}]*(?:^|[{;])\s*~/m) &&
      directive?(/#{S}\s*(root|log_format)\s[^;]*\$[1-9]/)
  end

  private

  def read_facts
    out = sh('command -v nginx >/dev/null 2>&1 || exit 0; nginx -V 2>&1; echo ===CONF===; nginx -T 2>/dev/null')
    s = sections(out)
    {
      version: s['head'].to_s[%r{nginx/(\d+\.\d+\.\d+)}, 1],
      configure: s['head'].to_s[/configure arguments:(.*)$/, 1].to_s,
      conf: strip_hash_comments(s['conf']),
    }
  end
end

class HttpdFacts < Inspec.resource(1)
  name 'httpd_facts'
  desc 'Apache httpd version, loaded modules and config'
  include FactsSupport

  def installed?
    !facts[:version].nil?
  end

  def version
    facts[:version]
  end

  # Debian/Ubuntu package name, for distro backport checks
  def package
    facts[:bin].to_s.include?('apache2') ? 'apache2' : 'httpd'
  end

  # Loaded module, e.g. module?('http2_module')
  def module?(mod)
    facts[:modules].include?(mod)
  end

  def modules_readable?
    !facts[:modules].empty?
  end

  # All included config files concatenated, comments removed
  def conf
    facts[:conf]
  end

  def conf_readable?
    !conf.strip.empty?
  end

  def directive?(regex)
    conf.match?(regex)
  end

  # HTTP/2 offered: "Protocols ... h2" or "h2c" anywhere in the config
  def http2_enabled?
    directive?(/^\s*Protocols\s[^\n]*\bh2c?\b/i)
  end

  private

  def read_facts
    out = sh(<<~'SH')
      B=$(command -v apache2ctl || command -v apachectl || command -v httpd) || exit 0
      echo "BIN=$B"; "$B" -v 2>&1
      echo ===MODULES===
      "$B" -M 2>/dev/null
      echo ===CONF===
      "$B" -t -D DUMP_INCLUDES 2>/dev/null | awk '/^[[:space:]]*\(/ {print $NF}' | while read -r f; do cat "$f" 2>/dev/null; echo; done
    SH
    s = sections(out)
    {
      bin: s['head'].to_s[/^BIN=(.*)$/, 1],
      version: s['head'].to_s[%r{Apache/(\d+\.\d+\.\d+)}, 1],
      modules: s['modules'].to_s.scan(/^\s*(\w+_module)\b/).flatten,
      conf: s['conf'].to_s.lines.reject { |l| l =~ /^\s*#/ }.join,
    }
  end
end

class TomcatFacts < Inspec.resource(1)
  name 'tomcat_facts'
  desc 'Apache Tomcat version and server.xml'
  include FactsSupport

  def installed?
    !facts[:version].nil?
  end

  def version
    facts[:version]
  end

  def home
    facts[:home]
  end

  # server.xml without XML comments
  def server_xml
    facts[:server_xml]
  end

  def server_xml_readable?
    !server_xml.strip.empty?
  end

  def http2?
    server_xml.include?('org.apache.coyote.http2.Http2Protocol')
  end

  # Every <Realm className="...JNDIRealm" ...> tag in server.xml, conf/context.xml,
  # conf/Catalina/*/*.xml and webapps/*/META-INF/context.xml
  def jndi_realms
    (server_xml + facts[:contexts]).scan(/<Realm\b[^>]*JNDIRealm[^>]*>/m)
  end

  # Attribute value from a tag string, or nil
  def attr(tag, name)
    tag[/\b#{name}\s*=\s*"([^"]*)"/, 1]
  end

  private

  def read_facts
    out = sh(<<~'SH')
      for h in "$CATALINA_HOME" /usr/local/tomcat /opt/tomcat /usr/share/tomcat* /opt/bitnami/tomcat; do
        [ -n "$h" ] && [ -f "$h/conf/server.xml" ] && { H=$h; break; }
      done
      [ -n "$H" ] || exit 0
      echo "HOME=$H"
      grep -h 'Apache Tomcat Version' "$H/RELEASE-NOTES" 2>/dev/null | head -n 1
      sh "$H/bin/version.sh" 2>/dev/null | grep 'Server number'
      echo ===XML===
      cat "$H/conf/server.xml" 2>/dev/null
      echo ===CONTEXTS===
      cat "$H"/conf/context.xml "$H"/conf/Catalina/*/*.xml "$H"/webapps/*/META-INF/context.xml 2>/dev/null
    SH
    s = sections(out)
    head = s['head'].to_s
    {
      home: head[/^HOME=(.*)$/, 1],
      version: head[/Apache Tomcat Version (\d+\.\d+\.\d+)/, 1] || head[/Server number:\s*(\d+\.\d+\.\d+)/, 1],
      server_xml: s['xml'].to_s.gsub(/<!--.*?-->/m, ''),
      contexts: s['contexts'].to_s.gsub(/<!--.*?-->/m, ''),
    }
  end
end

# ---------------------------------------------------------------------------
# Language runtimes
# ---------------------------------------------------------------------------
class PhpFacts < Inspec.resource(1)
  name 'php_facts'
  desc 'PHP version, ini values and FPM/Apache overrides'
  include FactsSupport

  def installed?
    !facts[:version].nil?
  end

  def version
    facts[:version]
  end

  def fpm?
    facts[:fpm]
  end

  # Effective value of an ini setting as a string. php_admin_* / php_*
  # overrides in FPM pools or Apache config win over php.ini, since those are
  # what the web server actually uses.
  def ini(key)
    facts[:overrides].fetch(key) { facts[:ini][key] }
  end

  # Boolean ini setting (On/1/true/yes)
  def ini_on?(key)
    %w[1 on true yes].include?(ini(key).to_s.strip.downcase)
  end

  private

  def read_facts
    out = sh(<<~'SH')
      command -v php >/dev/null 2>&1 || exit 0
      php -r 'echo "VERSION=", PHP_VERSION, "\n"; foreach (ini_get_all(null, false) as $k => $v) { echo "INI ", $k, "=", $v, "\n"; }'
      command -v php-fpm >/dev/null 2>&1 || ls /usr/sbin/php-fpm* /usr/local/sbin/php-fpm >/dev/null 2>&1 && echo FPM=1
      echo ===OVERRIDES===
      grep -rhsiE '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]*\[?' /etc/php* /usr/local/etc/php-fpm.d /usr/local/etc/php-fpm.conf /etc/apache2 /etc/httpd /usr/local/apache2/conf 2>/dev/null
    SH
    s = sections(out)
    head = s['head'].to_s
    ini = {}
    head.scan(/^INI ([^=\n]+)=(.*)$/) { |k, v| ini[k] = v }
    overrides = {}
    s['overrides'].to_s.each_line do |l|
      # FPM:    php_admin_value[session.upload_progress.enabled] = 0
      # Apache: php_admin_flag session.upload_progress.enabled off
      if (m = l.match(/php_(?:admin_)?(?:value|flag)\s*\[([^\]]+)\]\s*=\s*(\S+)/i) ||
              l.match(/php_(?:admin_)?(?:value|flag)\s+(\S+)\s+(\S+)/i))
        overrides[m[1]] = m[2].delete('"\'').sub(/;.*$/, '')
      end
    end
    {
      version: head[/^VERSION=(\d+\.\d+\.\d+)/, 1],
      ini: ini,
      overrides: overrides,
      fpm: head.include?('FPM=1'),
    }
  end
end

class NodeFacts < Inspec.resource(1)
  name 'node_facts'
  desc 'Node.js version'
  include FactsSupport

  def installed?
    !version.nil?
  end

  def version
    facts[:version]
  end

  private

  def read_facts
    out = sh('command -v node >/dev/null 2>&1 || exit 0; node -v 2>/dev/null')
    { version: out[/v?(\d+\.\d+\.\d+)/, 1] }
  end
end

class JavaFacts < Inspec.resource(1)
  name 'java_facts'
  desc 'Java runtime version, architecture, CPU flags, JVM options, JavaFX, Kerberos'
  include FactsSupport

  def installed?
    !version.nil?
  end

  # "21.0.13.1", "17.0.21", or "8u432" for Java 8
  def version
    facts[:version]
  end

  def arch
    facts[:arch]
  end

  # CPU feature flag from /proc/cpuinfo (the host CPU), e.g. cpu_flag?('avx512vbmi')
  def cpu_flag?(flag)
    facts[:cpu_flags].include?(flag)
  end

  # JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS / _JAVA_OPTIONS plus command lines of
  # running java processes, as one string
  def jvm_options
    facts[:opts]
  end

  def javafx?
    facts[:javafx]
  end

  # A Kerberos config exists (/etc/krb5.conf or -Djava.security.krb5.conf)
  def kerberos?
    facts[:krb5] || jvm_options.include?('java.security.krb5') || jvm_options.include?('Krb5LoginModule')
  end

  private

  def read_facts
    out = sh(<<~'SH')
      command -v java >/dev/null 2>&1 || exit 0
      java -version 2>&1
      echo ===ARCH===
      uname -m
      echo ===CPU===
      grep -m 1 '^flags' /proc/cpuinfo 2>/dev/null
      echo ===OPTS===
      echo "$JAVA_TOOL_OPTIONS $JDK_JAVA_OPTIONS $_JAVA_OPTIONS"
      for p in /proc/[0-9]*; do c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); case $c in *java*) echo "$c" ;; esac; done
      echo ===FX===
      java --list-modules 2>/dev/null | grep -i javafx | head -n 1
      ls "$JAVA_HOME"/lib/*jfxwebkit* "$JAVA_HOME"/lib/ext/jfxrt.jar 2>/dev/null | head -n 1
      echo ===KRB===
      [ -f /etc/krb5.conf ] && echo yes
    SH
    s = sections(out)
    raw = s['head'].to_s[/version "([^"]+)"/, 1].to_s
    v = if raw =~ /\A1\.8\.0_(\d+)/ then "8u#{Regexp.last_match(1)}"
        else raw[/\A\d+(\.\d+){0,3}/]
        end
    {
      version: v,
      arch: s['arch'].to_s.strip,
      cpu_flags: s['cpu'].to_s.sub(/\Aflags\s*:/, '').split,
      opts: s['opts'].to_s.gsub(/\s+/, ' '),
      javafx: !s['fx'].to_s.strip.empty?,
      krb5: s['krb'].to_s.include?('yes'),
    }
  end
end

class PythonFacts < Inspec.resource(1)
  name 'python_facts'
  desc 'CPython version'
  include FactsSupport

  def installed?
    !version.nil?
  end

  def version
    facts[:version]
  end

  private

  def read_facts
    out = sh('P=$(command -v python3 || command -v python) || exit 0; "$P" -c "import sys; print(sys.version.split()[0])" 2>/dev/null')
    { version: out[/(\d+\.\d+\.\d+)/, 1] }
  end
end

class DotnetFacts < Inspec.resource(1)
  name 'dotnet_facts'
  desc '.NET runtimes, NuGet packages in *.deps.json, runtime file ownership'
  include FactsSupport

  def installed?
    !facts[:runtimes].empty? || !facts[:packages].empty?
  end

  # Versions of one shared runtime, e.g. versions('Microsoft.AspNetCore.App')
  def versions(runtime = 'Microsoft.NETCore.App')
    facts[:runtimes].fetch(runtime, []).uniq
  end

  # Versions of a NuGet package referenced in any *.deps.json
  def package_versions(pkg)
    facts[:packages].fetch(pkg, []).uniq
  end

  # ASP.NET Core runtime files not owned by root or writable by others
  # (CVE-2026-114148); first offending path or nil
  def unsafe_runtime_file
    f = facts[:unsafe].strip
    f.empty? ? nil : f
  end

  private

  def read_facts
    out = sh(<<~'SH')
      { command -v dotnet >/dev/null 2>&1 && dotnet --list-runtimes 2>/dev/null; } || true
      ls -d /usr/share/dotnet/shared/*/* /usr/lib/dotnet/shared/*/* /opt/dotnet/shared/*/* "$DOTNET_ROOT"/shared/*/* 2>/dev/null
      echo ===DEPS===
      find / -xdev -maxdepth 4 -name '*.deps.json' -not -path '/proc/*' 2>/dev/null | head -n 50 | while read -r f; do
        grep -oE '"Microsoft\.AspNetCore\.[A-Za-z.]+/[0-9][^"]*"' "$f" 2>/dev/null
      done
      echo ===UNSAFE===
      for d in /usr/share/dotnet /usr/lib/dotnet /opt/dotnet "$DOTNET_ROOT"; do
        [ -d "$d/shared/Microsoft.AspNetCore.App" ] || continue
        find "$d/shared/Microsoft.AspNetCore.App" "$d/packs/Microsoft.AspNetCore.App.Ref" \( ! -uid 0 -o -perm -o+w \) 2>/dev/null | head -n 1
      done
    SH
    s = sections(out)
    runtimes = Hash.new { |h, k| h[k] = [] }
    s['head'].to_s.each_line do |l|
      if (m = l.match(/^(Microsoft\.[\w.]+) (\d+\.\d+\.\d+)/) || l.match(%r{/shared/(Microsoft\.[\w.]+)/(\d+\.\d+\.\d+)}))
        runtimes[m[1]] << m[2]
      end
    end
    packages = Hash.new { |h, k| h[k] = [] }
    s['deps'].to_s.scan(%r{"(Microsoft\.AspNetCore\.[A-Za-z.]+)/(\d+\.\d+\.\d+)}) { |pkg, v| packages[pkg] << v }
    { runtimes: runtimes, packages: packages, unsafe: s['unsafe'].to_s.lines.first.to_s }
  end
end

class RailsFacts < Inspec.resource(1)
  name 'rails_facts'
  desc 'Rails apps found by Gemfile.lock: gem versions, config, risky code patterns'
  include FactsSupport

  def installed?
    !facts[:apps].empty?
  end

  # [[app root, version], ...] for one gem across all apps found
  def gem_versions(gem)
    facts[:apps].map { |root, a| [root, a[:gems][gem]] if a[:gems][gem] }.compact
  end

  def uses_gem?(gem)
    !gem_versions(gem).empty?
  end

  # Concatenated config/application.rb, environments, initializers, cable.yml
  def config(root)
    facts[:apps].fetch(root, {})[:config].to_s
  end

  # True if any app's config matches
  def any_config?(regex)
    facts[:apps].keys.any? { |root| config(root).match?(regex) }
  end

  def all_config?(regex)
    !facts[:apps].empty? && facts[:apps].keys.all? { |root| config(root).match?(regex) }
  end

  # How often a call appears in app/ and lib/ of all apps ('each_key', 'safe_constantize')
  def code_uses(call)
    facts[:apps].values.sum { |a| a[:code][call].to_i }
  end

  def tool?(name)
    facts[:tools].include?(name)
  end

  # ImageMagick policy.xml contents (all versions found)
  def imagemagick_policy
    facts[:policy]
  end

  def rubygems_version
    facts[:rubygems]
  end

  private

  def read_facts
    out = sh(<<~'SH')
      command -v gem >/dev/null 2>&1 && echo "RUBYGEMS=$(gem --version 2>/dev/null)"
      for t in convert magick ffmpeg ffprobe; do command -v "$t" >/dev/null 2>&1 && echo "TOOL=$t"; done
      echo ===POLICY===
      cat /etc/ImageMagick-*/policy.xml /usr/local/etc/ImageMagick-*/policy.xml 2>/dev/null
      echo ===APPS===
      find / -xdev -maxdepth 5 -name Gemfile.lock -not -path '*/gems/*' -not -path '/proc/*' 2>/dev/null | head -n 20 | while read -r f; do
        r=$(dirname "$f")
        echo "@@APP $r"
        cat "$f"
        echo "@@CONFIG"
        cat "$r"/config/application.rb "$r"/config/environments/*.rb "$r"/config/initializers/*.rb "$r"/config/cable.yml 2>/dev/null
        echo "@@CODE"
        grep -rhoE '\beach_key\b|\bsafe_constantize\b' "$r/app" "$r/lib" 2>/dev/null | sort | uniq -c
      done
    SH
    head, rest = out.split("===POLICY===\n", 2)
    policy, apps_raw = rest.to_s.split("===APPS===\n", 2)
    apps = {}
    apps_raw.to_s.split(/^@@APP /).drop(1).each do |chunk|
      root, body = chunk.split("\n", 2)
      lock, after = body.to_s.split("@@CONFIG\n", 2)
      config, code = after.to_s.split("@@CODE\n", 2)
      gems = {}
      lock.to_s.scan(/^    ([a-z0-9_\-]+) \((\d+(?:\.\d+){1,3})[^)]*\)$/) { |g, v| gems[g] = v }
      counts = {}
      code.to_s.scan(/^\s*(\d+) (\S+)$/) { |n, call| counts[call] = n.to_i }
      apps[root.strip] = { gems: gems, config: config.to_s, code: counts }
    end
    {
      apps: apps,
      rubygems: head.to_s[/^RUBYGEMS=(\d+\.\d+\.\d+)/, 1],
      tools: head.to_s.scan(/^TOOL=(\S+)/).flatten,
      policy: policy.to_s,
    }
  end
end

# Go binaries of all running processes. On the host this includes every
# container's processes (also distroless ones), labelled by container name.
class GoFacts < Inspec.resource(1)
  name 'go_facts'
  desc 'Go toolchain version embedded in running binaries'
  include FactsSupport

  def installed?
    !binaries.empty?
  end

  # [{ label:, exe:, go: '1.25.3', xnet: '0.44.0' or nil, xnet_http2: bool,
  #    godebug: 'http2server=0' or '' }, ...]
  # xnet_http2: the binary uses golang.org/x/net/http2 directly (e.g. gRPC),
  # which GODEBUG http2server=0 does not switch off.
  def binaries
    facts[:binaries]
  end

  # [[label, version], ...] for cve_eval
  def go_versions
    binaries.map { |b| [b[:label], b[:go]] }.uniq
  end

  def xnet_versions
    binaries.select { |b| b[:xnet] }.map { |b| [b[:label], b[:xnet]] }.uniq
  end

  private

  def read_facts
    out = sh(<<~'SH')
      names=$(docker ps --no-trunc --format '{{.ID}} {{.Names}}' 2>/dev/null)
      for p in /proc/[0-9]*; do
        e=$(readlink "$p/exe" 2>/dev/null) || continue
        case $e in *' (deleted)') continue ;; esac
        cid=$(grep -oE '[0-9a-f]{64}' "$p/cgroup" 2>/dev/null | head -n 1)
        echo "$cid $p/exe $e"
      done | sort -u -k1,1 -k3,3 | while read -r cid path e; do
        v=$(LC_ALL=C grep -aoE 'go1\.[0-9]+\.[0-9]+' "$path" 2>/dev/null | sort | uniq -c | sort -rn | head -n 1 | awk '{print $2}')
        [ -n "$v" ] || continue
        x=$(LC_ALL=C grep -aoE 'golang\.org/x/net.v0\.[0-9]+\.[0-9]+' "$path" 2>/dev/null | head -n 1 | grep -oE '0\.[0-9]+\.[0-9]+')
        h=0; LC_ALL=C grep -aq 'golang\.org/x/net/http2\.' "$path" 2>/dev/null && h=1
        pid=${path%/exe}
        d=$(tr '\0' '\n' < "$pid/environ" 2>/dev/null | sed -n 's/^GODEBUG=//p' | head -n 1)
        n=host
        [ -n "$cid" ] && n=$(printf '%s\n' "$names" | awk -v id="$cid" '$1 == id {print $2}' | sed -E 's/\.[a-z0-9]{25}//g')
        [ -n "$n" ] || n=${cid:-host}
        echo "BIN $n|$e|$v|$x|$h|$d"
      done
    SH
    bins = out.scan(/^BIN (.*)$/).flatten.map do |l|
      label, exe, go, xnet, h2, godebug = l.split('|', 6)
      { label: "#{label}:#{File.basename(exe)}", exe: exe, go: go.sub(/\Ago/, ''),
        xnet: (xnet.nil? || xnet.empty? ? nil : xnet), xnet_http2: h2 == '1', godebug: godebug.to_s }
    end
    { binaries: bins }
  end
end

# Simple version facts for single binaries: sudo, curl, openssl, go toolchain
class ToolFacts < Inspec.resource(1)
  name 'tool_facts'
  desc 'Versions of sudo, curl and OpenSSL'
  include FactsSupport

  def installed?(tool)
    !version(tool).nil?
  end

  # sudo "1.9.16p2", curl "8.11.1", openssl "3.0.15", go (toolchain) "1.26.3"
  def version(tool)
    facts[tool.to_sym]
  end

  def curl_http2?
    facts[:curl_features].include?('HTTP2')
  end

  # Contents of /etc/sudoers and /etc/sudoers.d (comments removed)
  def sudoers
    facts[:sudoers]
  end

  private

  def read_facts
    out = sh(<<~'SH')
      command -v sudo >/dev/null 2>&1 && sudo -V 2>/dev/null | head -n 1
      command -v curl >/dev/null 2>&1 && curl -V 2>/dev/null
      command -v openssl >/dev/null 2>&1 && openssl version 2>/dev/null
      command -v go >/dev/null 2>&1 && go version 2>/dev/null
      echo ===SUDOERS===
      cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
    SH
    s = sections(out)
    head = s['head'].to_s
    {
      sudo: head[/Sudo version (\d+\.\d+\.\d+(?:p\d+)?)/, 1],
      curl: head[/^curl (\d+\.\d+\.\d+)/, 1],
      curl_features: head[/^Features:(.*)$/, 1].to_s.split,
      openssl: head[/^OpenSSL (\d+\.\d+\.\d+)/, 1],
      go: head[/^go version go(\d+\.\d+(?:\.\d+)?)/, 1],
      sudoers: s['sudoers'].to_s.lines.reject { |l| l =~ /^\s*#(?!include)/ }.join,
    }
  end
end
