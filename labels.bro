@load flow_labels


export {

	redef Netbase::observation += {
	    # Label fields
	    ip_labels: set[string] &optional &log;
	    flow_labels: set[string] &optional &log;
	};
}

# Function to gather labels 
function get_labels(c: connection)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    if ( c?$labels )
        {
        if ( orig in profiles && c$labels?$orig && |c$labels$orig| > 0 )
            {
            for ( ol in c$labels$orig )
                {
                add profiles[orig]$ip_labels[ol];   
                }
            
            if ( c$labels?$flow && |c$labels$flow| > 0 )
                {
                for ( ofl in c$labels$flow )
                    {
                    add profiles[orig]$flow_labels[ofl];
                    }                   
                }
            }
        
        if ( resp in profiles && c$labels?$resp && |c$labels$resp| > 0 )
            {
            for ( rl in c$labels$resp )
                {
                add profiles[resp]$ip_labels[rl];
                }           
        
            if ( c$labels?$flow && |c$labels$flow| > 0 )
                {
                for ( rfl in c$labels$flow )
                    {
                    add profiles[resp]$flow_labels[rfl];
                    }
                }
            }           
        }
    }

event flow_labeled(c: connection)
    {
    #  Do nothing if we are missing conn Info record or needed site fields
    if ( ! c?$conn || (! c$conn?$local_orig || ! c$conn?$local_resp ))
        {
        return;
        }
    
    # Make sure we have profiles for these IPs
    get_labels(c);
    }

