module Rouge
  module Lexers
    class JunFire < RegexLexer
      title "Juniper Firewall"
      desc "Juniper Firewall set commands and similar"
      tag 'junfire'
      filenames '*.fw'

      # Name::Constant - light green
      # Name::Function - blue
      # Name::Class - dark blue
      # Keyword - black
      # Operator - blue

      state :root do
        rule %r/^#[^\n]*/, Comment
        rule %r/^set filter /, Keyword, :setfilter
        rule %r/^set groups /, Keyword, :setgroups
        rule %r/^set policy-options /, Keyword, :setpolicy
        rule %r/^set security policies from-zone /, Keyword, :secpolicyfrom
      end

      # security policy -------------------------------------------------------------------------------------

      state :secpolicyfrom do
        rule %r/\n/, Text, :root
        rule %r/\S+ /, Name::Class, :secpolicytozone
      end

      state :secpolicytozone do
        rule %r/\n/, Text, :root
        rule %r/to-zone /, Keyword, :secpolicyto
      end

      state :secpolicyto do
        rule %r/\n/, Text, :root
        rule %r/\S+ /, Name::Class, :secpolicypolicy
      end

      state :secpolicypolicy do
        rule %r/\n/, Text, :root
        rule %r/policy /, Keyword, :secpolicyname
      end

      state :secpolicyname do
        rule %r/\n/, Text, :root
        rule %r/\S+ /, Name::Class, :secpolicyaction
      end

      state :secpolicyaction do
        rule %r/\n/, Text, :root
        rule %r/apply-groups /, Keyword, :anytail
        rule %r/match (source|destination)-address /, Keyword, :anytail
        rule %r/match application /, Keyword, :anytail
      end



      # set groups -------------------------------------------------------------------------------------

      state :setgroups do
        rule %r/\n/, Text, :root
        rule %r/\S+ /, Name::Class, :group
      end

      state :setpolicy do
        rule %r/\n/, Text, :root
        rule %r/prefix-list /, Keyword, :policyprefixname
      end

      state :policyprefixname do
        rule %r/\n/, Text, :root
        rule %r/\S+ /, Name::Class, :address
      end

      state :policy do
        rule %r/\n/, Text, :root
      end

      state :group do
        rule %r/\n/, Text, :root
        rule %r/firewall family inet filter \<\*\> /, Keyword, :term
        rule %r/interfaces \<\*\> unit \d family ethernet-switching /, Keyword, :anytail
        rule %r/protocols protection-group ethernet-ring \<\*\> data-channel /, Keyword, :anytail
      end

      state :groupname do
        rule %r/\n/, Text, :root
        rule %r/\S+/, Name::Class, :root
      end

      # set filter -------------------------------------------------------------------------------------

      state :setfilter do
        rule %r/\n/, Text, :root
        rule %r/\S+ /, Name::Class, :term
      end



      state :term do
        rule %r/\n/, Text, :root
        rule %r/term /, Keyword, :termname
        rule %r/apply-groups /, Keyword, :groupname
      end

      state :termname do
        rule %r/\n/, Text, :root
        rule %r/\S+ /, Name::Class, :termaction
      end



      state :termaction do
        rule %r/\n/, Text, :root
        rule %r/from /, Keyword, :termfrom
        rule %r/then /, Keyword, :termthen
      end

      state :termfrom do
        rule %r/\n/, Text, :root
        rule %r/(source|destination)-address /, Operator, :address
        rule %r/(source|destination)-port /, Operator, :port
        rule %r/(source|destination)-prefix-list /, Operator, :preflist
        rule %r/protocol /, Operator, :protocol
        rule %r/icmp-type /, Operator, :icmptype
        rule %r/tcp-established/, Operator, :root
      end

      state :icmptype do
        rule %r/\n/, Text, :root
        rule %r/(echo-request|echo-reply|unreachable)/, Operator, :root
      end

      state :termthen do
        rule %r/\n/, Text, :root
        rule %r/(accept|discard|syslog|reject)/, Operator, :root
      end

      state :protocol do
        rule %r/\n/, Text, :root
        rule %r/(udp|tcp|icmp|ip)/, Name::Variable, :root
      end



      state :port do
        rule %r/\n/, Text, :root
        rule %r/\d{1,5}(-\d{1,5})?/, Name::Variable, :root
      end

      state :preflist do
        rule %r/\n/, Text, :root
        rule %r/\S+/, Name::Variable, :root
      end

      # common -------------------------------------------------------------------------------------

      state :anytail do
        rule %r/.+\n/, Text, :root
      end

      state :address do
        rule %r/\n/, Text, :root
        rule %r/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?/, Name::Variable, :root
      end

    end
  end
end
