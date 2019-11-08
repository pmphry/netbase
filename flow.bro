@load ./main
@load base/utils/directions-and-hosts

module Netbase;

export {

    redef record Netbase::observation += {
        int_ports: set[string] &optional;                  # Unique ports communicated with internally
        int_port_cnt: count &default=0 &log;               # Count of unique ports communicated with internally
        int_hosts: set[string] &optional;                  # Unique hosts communicated with internally
        int_host_cnt: count &default=0 &log;               # Count of unique hosts communicated with internally
        ext_ports: set[string] &optional;                  # Unique ports communicated with externally
        ext_port_cnt: count &default=0 &log;               # Count of unique ports communicated with externally
        ext_hosts: set[string] &optional;                  # Unique IP's communicated with externally
        ext_host_cnt: count &default=0 &log;               # Count of unique hosts communicated with externally
        int_clients: set[string] &optional;                # Unique internal clients communicating with this IP
        int_client_cnt: count &default=0 &log;             # Count of unique internal clients communicating with this IP
        ext_clients: set[string] &optional;                # Unique external clients communicating with this IP
        ext_client_cnt: count &default=0 &log;             # Count fo unique external clients communicating with this IP
        total_conns: count &default=0 &log;                # Total count of connections this IP was involved in
        out_orig_conns: count &default=0 &log;             # Total count of external conns originated by this IP
        out_succ_conns: count &default=0 &log;             # Count of outbound conns originated by this IP that were successful
        out_rej_conns: count &default=0 &log;              # Count of outbound conns originated by this IP that were rejected
        out_to_highports: count &default=0 &log;           # Count of outbound conns originated by this IP to ports >= 1024
        out_to_lowports: count &default=0 &log;            # Count of outbound conns originated by this IP to ports < 1024
        out_to_service: count &default=0 &log;             # Count of outbound conns to a recognized service (service field populated)
        int_orig_conns: count &default=0 &log;             # Total count of internal conns originated by this host   <-- 
        int_rej_conns: count &default=0 &log;              # Count of internal conns originated by this host that were rejected
        int_to_highports: count &default=0 &log;           # Count of internal conns to ports >= 1024
        int_to_lowports: count &default=0 &log;            # Count of internal conns to ports < 1024     
        int_to_service: count &default=0 &log;             # Count of internal conns to recognized server (service field populated)
        int_resp_conns: count &default=0 &log;             # Count of internal conns this IP responded to 
        int_orig_bytes_sent: count &default=0 &log;        # Sum of bytes sent as originator in internal conns
        int_orig_bytes_rcvd: count &default=0 &log;        # Sum of bytes received as originator in internal conns 
        out_orig_bytes_sent: count &default=0 &log;        # Sum of bytes sent as originator in external conns
        out_orig_bytes_rcvd: count &default=0 &log;        # Sum of bytes received as originator in external conns
        int_orig_pkts_sent: count &default=0 &log;         # Count of packets sent in internal conns 
        int_orig_pkts_recvd: count &default=0 &log;        # Count of packets recevied in internal conns
        out_orig_pkts_sent: count &default=0 &log;         # Count of packets sent as originator in outbound conns
        out_orig_pkts_recvd: count &default=0 &log;        # Count of packets received as originator in outbound conns 
        ## PCR stats for internal tcp conns
        pcr_int_tcp: Netbase::numstats &default=Netbase::numstats();
        pcr_int_tcp_avg: double &optional &log;
        pcr_int_tcp_max: double &optional &log;
        pcr_int_tcp_min: double &optional &log;
        ## PCR stats for internal udp conns
        pcr_int_udp: Netbase::numstats &default=Netbase::numstats();
        pcr_int_udp_avg: double &optional &log;
        pcr_int_udp_max: double &optional &log;
        pcr_int_udp_min: double &optional &log;
        ## PCR stats for internal smb conns
        pcr_int_smb: Netbase::numstats &default=Netbase::numstats();
        pcr_int_smb_avg: double &optional &log;
        pcr_int_smb_max: double &optional &log;
        pcr_int_smb_min: double &optional &log;
        ## PCR stats for outbound http conns
        pcr_out_http: Netbase::numstats &default=Netbase::numstats();
        pcr_out_http_avg: double &optional &log;
        pcr_out_http_max: double &optional &log;
        pcr_out_http_min: double &optional &log;
        ## PCR stats for outbound dns conns
        pcr_dns: Netbase::numstats &default=Netbase::numstats();
        pcr_dns_avg: double &optional &log;
        pcr_dns_max: double &optional &log;
        pcr_dns_min: double &optional &log;
        ## PCR stats for outbound https conns
        pcr_out_https: Netbase::numstats &default=Netbase::numstats();
        pcr_out_https_avg: double &optional &log;
        pcr_out_https_max: double &optional &log;
        pcr_out_https_min: double &optional &log;
    };
}

# Function to gather flow stats for IPs in a given connection 
function Netbase::get_flow_obs(c: connection, do_orig: bool, do_resp: bool)
    {
    if ( ! do_orig && ! do_resp )
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    local pkg = observables();

    if ( do_orig )
        {
        pkg[orig] = set([$name="total_conns"]);        
        }

    if ( do_resp )
        {
        pkg[resp] = set([$name="total_conns"]);
        }

    local rp = port_to_count(c$id$resp_p); 

    #  Internal -> external flow?
    if ( id_matches_direction(c$id, OUTBOUND) )
        {
        add pkg[orig][[$name="ext_ports", $val=cat(c$id$resp_p)]];
        add pkg[orig][[$name="ext_hosts", $val=cat(c$id$resp_h)]];
        add pkg[orig][[$name="out_orig_conns"]];

        if ( c$orig?$size )
            {
            add pkg[orig][[$name="out_orig_bytes_sent", $val=cat(c$orig$size)]];
            }

        if ( c$resp?$size )
            {
            add pkg[orig][[$name="out_orig_bytes_rcvd", $val=cat(c$resp$size)]];
            }

        if ( c$orig?$num_pkts )
            {
            add pkg[orig][[$name="out_orig_pkts_sent", $val=cat(c$orig$num_pkts)]];
            }

        if ( c$resp?$num_pkts )
            {
            add pkg[orig][[$name="out_orig_pkts_recvd", $val=cat(c$resp$num_pkts)]];
            }

        if ( c$conn?$conn_state )
            {
            switch (c$conn$conn_state)
                {
                case "SF":
                    add pkg[orig][[$name="out_succ_conns"]];
                    break;
                case "REJ":
                    add pkg[orig][[$name="out_rej_conns"]];
                    fallthrough;                    
                }
            }
        
        if ( rp >= 1024)
            {
            add pkg[orig][[$name="out_to_highports"]];
            }
        else if ( rp < 1024 ) 
            {
            add pkg[orig][[$name="out_to_lowports"]];
            }

        if ( c?$service && |c$service| > 0 )
            {
            add pkg[orig][[$name="out_to_service"]];
            if ( "DNS" in c$service && c$conn?$pcr )
                {
                add pkg[orig][[$name="pcr_dns", $val=cat(c$conn$pcr)]];
                }
            }
        }   
    # Internal -> internal flow?
    else if ( addr_matches_host(orig,LOCAL_HOSTS) && addr_matches_host(resp,LOCAL_HOSTS) )
        {
        add pkg[orig][[$name="int_ports", $val=cat(c$id$resp_p)]];
        add pkg[orig][[$name="int_hosts", $val=cat(resp)]];
        add pkg[orig][[$name="int_orig_conns"]];

        if ( do_resp )
            {
            add pkg[resp][[$name="int_clients", $val=cat(orig)]];
            add pkg[resp][[$name="int_resp_conns"]];           
            }

        if ( c$orig?$size )
            {
            add pkg[orig][[$name="int_orig_bytes_sent", $val=cat(c$orig$size)]];
            }

        if ( c$resp?$size )
            {
            add pkg[orig][[$name="int_orig_bytes_rcvd", $val=cat(c$resp$size)]];
            }

        if ( c$orig?$num_pkts )
            {
            add pkg[orig][[$name="int_orig_pkts_sent", $val=cat(c$orig$num_pkts)]];
            }

        if ( c$resp?$num_pkts )
            {
            add pkg[orig][[$name="int_orig_pkts_recvd", $val=cat(c$resp$num_pkts)]];
            }

        if ( c$conn?$conn_state )
            {
            switch (c$conn$conn_state)
                {
                case "SF":
                    add pkg[orig][[$name="int_conns"]];
                    break;
                case "REJ":
                    add pkg[orig][[$name="int_rej_conns"]];
                    fallthrough;
                }
            }
         
        if ( rp >= 1024)
            {
            add pkg[orig][[$name="int_to_highports"]];
            }
        else if ( rp < 1024 ) 
            {
            add pkg[orig][[$name="int_to_lowports"]];
            }

        if ( c?$service && |c$service| > 0 )
            {         
            add pkg[orig][[$name="int_to_service"]]; 
            if ( "DNS" in c$service && c$conn?$pcr )
                {
                add pkg[orig][[$name="pcr_dns", $val=cat(c$conn$pcr)]];
                }
            }
        }
    # External -> internal flow?
    else if ( id_matches_direction(c$id, INBOUND) && /^255\.|\.255$/ !in cat(resp) )
        {
        add pkg[resp][[$name="server_conns"]];
        add pkg[resp][[$name="ext_clients", $val=cat(orig)]];
        }

    # See if the observable pkgs need delivering
    if ( orig in pkg )
        {
        Netbase::SEND(orig, pkg[orig]);
        }

    if ( resp in pkg )
        {
        Netbase::SEND(resp, pkg[resp]);
        }
    }

# Handler for grabbing unique value counts for logging
event Netbase::log_observation(obs: observation)
    {
    obs$int_port_cnt = |obs$int_ports|;
    obs$int_host_cnt = |obs$int_hosts|;
    obs$ext_port_cnt = |obs$ext_ports|; 
    obs$ext_host_cnt = |obs$ext_hosts|;

    obs$int_client_cnt = |obs$int_clients|;
    obs$ext_client_cnt = |obs$ext_clients|;

    if ( obs$pcr_dns$cnt > 0 ) 
        {
        obs$pcr_dns_avg = obs$pcr_dns$avg;
        obs$pcr_dns_max = obs$pcr_dns$max;
        obs$pcr_dns_min = obs$pcr_dns$min;
        }
    }

# Hook handler to initialize sets 
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
     {           
     obs[ip]$int_ports=set();
     obs[ip]$int_hosts=set();
     obs[ip]$ext_ports=set();
     obs[ip]$ext_hosts=set();
     obs[ip]$int_clients=set();
     obs[ip]$ext_clients=set();
     }

# Handler to load observables into the observations table
# This event is executed every time a node calls the SEND()
# function.  
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "int_ports":
                add observations[ip]$int_ports[o$val];
                break;
            case "int_hosts":
                add observations[ip]$int_hosts[o$val];
                break;
            case "ext_ports":
                add observations[ip]$ext_ports[o$val];
                break;
            case "ext_hosts":
                add observations[ip]$ext_hosts[o$val];
                break;
            case "int_clients":
                add observations[ip]$int_clients[o$val];
                break;
            case "ext_clients":
                add observations[ip]$ext_clients[o$val];
                break;
            case "total_conns":
                ++observations[ip]$total_conns;
                break;
            case "out_succ_conns":
                ++observations[ip]$out_succ_conns;
                break;
            case "out_rej_conns":
                ++observations[ip]$out_rej_conns;
                break;
            case "out_to_highports":
                ++observations[ip]$out_to_highports;
                break;
            case "out_to_lowports":
                ++observations[ip]$out_to_lowports;
                break;
            case "out_to_service":
                ++observations[ip]$out_to_service;
                break;
            case "int_orig_conns":
                ++observations[ip]$int_orig_conns;
                break;
            case "int_rej_conns":
                ++observations[ip]$int_rej_conns;
                break;
            case "int_to_highports":
                ++observations[ip]$int_to_highports;
                break;
            case "int_to_lowports":
                ++observations[ip]$int_to_lowports;
                break;
            case "int_to_service":
                ++observations[ip]$int_to_service;
                break;
            case "int_resp_conns":
                ++observations[ip]$int_resp_conns;
                break;
            case "int_orig_bytes_sent":
                observations[ip]$int_orig_bytes_sent = observations[ip]$int_orig_bytes_sent + to_count(o$val);
                break;
            case "int_orig_bytes_rcvd":
                observations[ip]$int_orig_bytes_rcvd = observations[ip]$int_orig_bytes_rcvd + to_count(o$val);
                break;
            case "out_orig_bytes_sent":
                observations[ip]$out_orig_bytes_sent = observations[ip]$out_orig_bytes_sent + to_count(o$val);
                break;
            case "out_orig_bytes_rcvd":
                observations[ip]$out_orig_bytes_rcvd = observations[ip]$out_orig_bytes_rcvd + to_count(o$val);
                break;
            case "int_orig_pkts_sent":
                observations[ip]$int_orig_pkts_sent = observations[ip]$int_orig_pkts_sent + to_count(o$val);
                break;
            case "int_orig_pkts_recvd":
                observations[ip]$int_orig_pkts_recvd = observations[ip]$int_orig_pkts_recvd + to_count(o$val);
                break;
            case "out_orig_pkts_sent":
                observations[ip]$out_orig_pkts_sent = observations[ip]$out_orig_pkts_sent + to_count(o$val);
                break;
            case "out_orig_pkts_recvd":
                observations[ip]$out_orig_pkts_recvd = observations[ip]$out_orig_pkts_recvd + to_count(o$val);
                break;
            case "pcr_dns":
                observations[ip]$pcr_dns = Netbase::update_numstats(observations[ip]$pcr_dns, to_double(o$val));
                break;
            }       
        }
    }
@endif

# Hanndler to vet the connection and start observations
event connection_state_remove(c: connection)
    {
    if ( ! c?$id )
        return;
    
    Netbase::get_flow_obs(c, Netbase::is_monitored(c$id$orig_h), Netbase::is_monitored(c$id$resp_h));
    }







