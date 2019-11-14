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
    if ( ! Netbase::is_monitored(host) )
        return;

    local pkg = observables(
            [host] = set();
        );
    # if its server software log it seperately 
    if ( info?$software_type && "SERVER" in cat(info$software_type) )
        {
        # check if we have a port 
        if ( info?$host_p )
            {
            # if there is a port, observe it 
            add pkg[host][[
                    $name="server_ports",
                    $val=cat(info$software_type + '_' + cat(info$host_p))
                ]];
            }
        else 
        # no port 
            {
            add pkg[host][[
                    $name="server_ports",
                    $val=cat(info$software_type + '_' + 'ukn')
                ]];
            }
        }

    # log name and version, these combined should be unique-ish 
    if ( info?$name && info?$unparsed_version )
        {
        add pkg[host][[
                $name="apps",
                $val=cat(info$name + '_' + info$unparsed_version)
            ]];
        }

    if ( |pkg[host]| > 0 )
        {
        # send it
        Netbase::SEND(pkg[host]); 
        }
    }

event Software::version_change(old: Software::Info, new: Software::Info)
    {
    # observe app updates 
    if ( new?$name && new?$unparsed_version )
        {
        add pkg[host][[
                $name="updated_apps",
                $val=cat(new$name + '_' + new$unparsed_version)
            ]];
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
                add observations[ip]$app[o$val];
                break;
            case "updated_apps":
                add observations[ip]$updated_apps[o$val];
                break;
            }       
        }
    }
@endif





