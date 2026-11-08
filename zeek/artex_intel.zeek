# ARTEX / CyberStrikeAI intel for Zeek (Security Onion, Corelight, vanilla Zeek)
# 1. Copy feeds/artex_intel.dat to your intel directory (Security Onion: /opt/so/saltstack/local/salt/zeek/policy/intel/)
# 2. @load this script from local.zeek
# Hits land in intel.log; notices in notice.log.

@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += { "/opt/zeek/share/zeek/site/intel/artex_intel.dat" };  # adjust path

# feeds/artex_intel.dat sets meta.do_notice=T, so every hit also raises Intel::Notice.

module ArtexHunt;

export {
    redef enum Notice::Type += { LLM_API_From_Server };
    ## Put your server subnets here. LLM API egress from these is unusual.
    const server_nets: set[subnet] = { 10.10.0.0/16 } &redef;
    const llm_sni_patterns = /(^|\.)(api\.deepseek\.com|open\.bigmodel\.cn|xcai\.pro)$/ &redef;
}

event ssl_established(c: connection)
    {
    if ( ! c$ssl?$server_name ) return;
    if ( c$id$orig_h !in server_nets ) return;
    if ( llm_sni_patterns !in c$ssl$server_name ) return;
    NOTICE([$note=LLM_API_From_Server, $conn=c,
            $msg=fmt("Server %s reached LLM API %s", c$id$orig_h, c$ssl$server_name),
            $identifier=cat(c$id$orig_h, c$ssl$server_name),
            $suppress_for=1hr]);
    }
