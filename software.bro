@load ./main
@load base/utils/directions-and-hosts

# Load software stuff
@load protocols/ftp/software
@load protocols/dhcp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/detect-webapps
@load protocols/http/software-browser-plugins
@load protocols/http/software
@load protocols/mysql/software

module Netbase;

export {

    redef record Netbase::observation += {
        software: set[string] &log &optional;
        updated_software: set[string] &log &optional;
    };
}

# Hook handler to initialize sets 
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
     {           
     obs[ip]$software=set();
     obs[ip]$updated_software=set();
     }

function get_ver_string(v: Software::Info): string
    {
    if ( ! v?$version )
        return "unkn";

    local ver_string = "";
    if ( ! v$version?$major )
        return "unkn";
    else 
        {
        ver_string = cat(v$version$major);
        }
        
    if ( v$version?$minor )
        ver_string = fmt("%s.%s", ver_string, cat(v$version$minor));
    
    if ( v$version?$minor2 )
        ver_string = fmt("%s.%s", ver_string, cat(v$version$minor2));

    if ( v$version?$minor3 )
        ver_string = fmt("%s.%s", ver_string, cat(v$version$minor3));

    return ver_string;
    }

event Software::register(info: Software::Info)
    {
    if ( ! info?$host || ! Netbase::is_monitored(info$host) )
        return;

    local pkg = observables();

    pkg[info$host] = set();

    local s = "";

    if ( ! info?$software_type )
        return;
    else 
        s = cat(info$software_type);

    if ( info?$name && |info$name| > 0 )
        s = fmt("%s_%s", s, info$name);
    else 
        s = fmt("%s_%s", s, "unkn");

    s = fmt("%s_%s", s, get_ver_string(info));

    add pkg[info$host][[
            $name="software",
            $val=s
        ]];

    if ( |pkg[info$host]| > 0 )
        {
        Netbase::SEND(info$host, pkg[info$host]); 
        }
    }

event Software::version_change(old: Software::Info, new: Software::Info)
    {
    # observe app updates
    if ( ! new?$host || ! Netbase::is_monitored(new$host) )
        return;

    local pkg = observables();
    pkg[new$host] = set();

    local s = "";

    if ( ! new?$software_type )
        return;
    else 
        s = cat(new$software_type);

    if ( new?$name && |new$name| > 0 )
        s = fmt("%s_%s", s, new$name);
    else 
        s = fmt("%s_%s", s, "unkn");

    s = fmt("%s_%s", s, get_ver_string(new));

    add pkg[new$host][[
            $name="updated_software",
            $val=s
        ]];

    if ( |pkg[new$host]| > 0 )
        {
        Netbase::SEND(new$host, pkg[new$host]); 
        }
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "software":
                add observations[ip]$software[o$val];
                break;
            case "updated_software":
                add observations[ip]$updated_software[o$val];
                break;
            }       
        }
    }
@endif
