#

@load base/utils/directions-and-hosts 
# @load user_custom/flow_labels   # Add me later... 

# Define module namespace
module Netbase;

# Declare exports 
export {
    # Register the Log ID
    redef enum Log::ID += { LOG };

    # Declare observation record 
    type observation: record {
        address: addr &log &optional;
        starttime: time &log &optional;
        endtime: time &log &optional;
    };

    global close_obs: function(data: table[addr] of observation, idx: addr): interval;

    # Container for baseline observations
    global observations: table[addr] of observation = table() &create_expire=5 mins &expire_func=close_obs;  # <-- CHANGE ME

    # Event executed when preparing an observation for logging 
    global log_observation: event(p: Netbase::observation);

    #  Event executed when an observation is written to the log 
    global write_obs_log: event(p: Netbase::observation);

    # Type for sharing specific observations with proxies 
    type observable: record { 
        name: string;
        val: string &optional;
    };

    # Function for publishing observables to the proxy pool 
    global SEND: function(ip: addr, obs: set[observable]);

    # Reusable table type for temporary storage 
    # of observables inside event handlers
    type observables: table[addr] of set[observable];

    # Hook for external scripts to customize fields in the observation entry 
    global customize_obs: hook(ip: addr, observations: table[addr] of observation);

    # Event for sending/receiving observables 
    global add_observables: event(ip: addr, pkg: set[observable]);
}

# Function for sending observables from workers to proxies  
function SEND(ip: addr, obs: set[observable])
    {
    Cluster::publish_hrw(Cluster::proxy_pool, ip, add_observables, ip, obs);
    event Netbase::add_observables(ip, obs);         
    }

# Low priority event handler to write the observation to the log stream
# Any handlers that need to modify the record should be set to run at a higher 
# priority
event log_observation(obs: observation) &priority=-5
    {
    # Write the IP observation log entry. Only proxies do this 
    # in a cluster   
    @if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
        Log::write(Netbase::LOG, obs);
    @endif
    }

# Function to handle expiring observations
function close_obs(data: table[addr] of observation, idx: addr): interval 
    {
    #  Set the endtime 
    data[idx]$endtime = network_time();

    # Event for handling by other scripts to update fields 
    # before the observation is logged 
    event Netbase::log_observation(data[idx]);

    # Expire the entry now
    return 0 secs;
    }

# Drop local suppression cache on workers to force HRW key repartitioning.
#   Taking the lead from known_hosts here...  
event Cluster::node_up(name: string, id: string)
    {
    if ( Cluster::local_node_type() != Cluster::WORKER )
        return;

    Netbase::observations = table();
    }

# Drop local suppression cache on workers to force HRW key repartitioning.
#   Taking the lead from known_hosts here, agian...  
event Cluster::node_down(name: string, id: string)
    {
    if ( Cluster::local_node_type() != Cluster::WORKER )
        return;

    Netbase::observations = table();
    }

# Function to start observing for the provided IP
# Primary reason for this is to set starttime and 
# initialize sets for unique values 
function start_obs(ip: addr) 
    {
    if ( addr_matches_host(ip, LOCAL_HOSTS) )
        {
        observations[ip] = [$address=ip,$starttime=network_time()];

        # Hook for allowing other scripts to modify the observation 
        # table. Mainly so scripts can initialize any 
        # set fields they are using 
        hook Netbase::customize_obs(ip, observations);
        }
    }

# Handler to ensure the IP observation record exists in the table
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY ) 
event Netbase::add_observables(ip: addr, obs: set[observable]) &priority=10
    {
    if ( ip !in observations ) 
        {
        Netbase::start_obs(ip);
        }  
    }
@endif

# Create the log stream 
event bro_init()
    {
    Log::create_stream(Netbase::LOG, [$columns=observation, $ev=Netbase::write_obs_log, $path="netbase"]);
    }