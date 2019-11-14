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
        server_ports: set[string] &log &optional;
        apps: set[string] &log &optional;
        updated_apps: set[string] &log &optional;
    };
}

# Hook handler to initialize sets 
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
     {           
     obs[ip]$server_ports=set();
     obs[ip]$apps=set();
     obs[ip]$updated_apps=set();
     }

event Software::register(info: Software::Info)
    {
    if ( ! info?$host || ! Netbase::is_monitored(info$host) )
        return;

    local pkg = observables(
            [info$host] = set()
        );

    # if it's server software log it seperately 
    if ( info?$software_type && "SERVER" in cat(info$software_type) )
        {
        local prt = info?$host_p ? cat(info$host_p) : "ukn";
        add pkg[info$host][[
                $name="server_ports",
                $val=fmt("%s_%s", cat(info$software_type), prt)
            ]];
        }
    
    # log name and version, these combined should be unique-ish 
    if ( info?$name ) 
        {
        local ver = info?$unparsed_version && |info$unparsed_version| > 0 ? info$unparsed_version : "ukn";
        add pkg[info$host][[
                $name="apps",
                $val=fmt("%s_%s", info$name, ver)
            ]];
        }

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

    local pkg = observables(
            [new$host] = set()
        );

    if ( new?$name )
        {
        local ver = new?$unparsed_version && |new$unparsed_version| > 0 ? new$unparsed_version : "ukn";
        add pkg[new$host][[
                $name="apps",
                $val=fmt("%s_%s", new$name, ver)
            ]];
    }

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
            case "server_ports":
                add observations[ip]$server_ports[o$val];
                break;
            case "apps":
                add observations[ip]$apps[o$val];
                break;
            case "updated_apps":
                add observations[ip]$updated_apps[o$val];
                break;
            }       
        }
    }
@endif
