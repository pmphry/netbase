# Background

One of the biggest challenges we face as network traffic analysts is determining whether or not the traffic we are currently looking at is normal.  Normal is inherently difficult to define in a network environment.  What can be considered normal varies widely across devices.  Servers behave differently than workstations, domain controllers behave differently than database systems and so on.  Normal can also vary over time.  What is normal for a given host in the middle of a workday is usually very different than the behavior expected in the middle of the night.  

So as we try to determine if some traffic is normal, we ask oursevles questions like is this normal for this network? for this type of host? for this specific host? for this time of day? for this particular day of the week? Answering these questions requires lots of contextual knowledge, experience in the environment, and access to data that provides the right insights.  Obtaining these things is not trivial.  

One way to accomplish this is to make running observations of things that can then be compared.  A baseline, by definition, is a "minimum or starting point used for comparison".  Perfect, baselining sounds like a great fit, but how do you create one?  

# Netbase 

Netbase, short for Network Baseliner, is a Zeek framework aimed at helping you do just that.  By creating a running record of quantitative observations about network device activity it provides data points that can be compared to one another across several dimensions and analyzed manually, visually or statistically.  

Netbase uses a device-centric approach to capturing observations, specifically, the observations it logs describe activity from the perspective of each active, _monitored_ host (more on monitored hosts below).  When an IP address is active on the network, Netbase begins recording a wide variety of observations over a finite time interval.  At the end of the interval, an entry is written to the Netbase log stream containing the metrics that describe the devices activity in that timeframe, then the interval timer resets.     

# Netbase Structure 

Netbase is meant to work best in Zeek clusters, although it functions just fine on a stand-alone instance.  In clusters, more than one worker node performs traffic analysis and categorization tasks and records them in the form of observables (more on that below).  

When a worker finishes its analysis of a given connection it sends any recorded observables to the Proxy node(s) using Zeek's data partitioning API, which allows us to evenly spread keys in a table across multiple nodes in the cluster.  The Proxies process observables and associate them with the monitored IP address to which they apply, and regularly (on a set interval) log a summary of observations to the Netbase log stream. 

High-level depiction of Netbase's structure and data flow. 
<p align="center">
 <img width="auto" height="auto" src="/images/netbase_structure.png">
</p>

# Observables 

Netbase's primary goal is turn interesting network device activity into quantitative metrics that can be analyzed and compared at scale, these metrics are referred to as _observables_.  What is considered _interesting activity_ is highly subjective though.  There are many, many inferences one can make by analyzing any one of Zeek's native logs.  The approach here is simple, try to be comprehensive.  Cover device behaviors that apply to all types of hosts with the understanding that not all observables will apply to every host - and that's ok.  

There are a few fundamental types of observables, they are:
* Counts of specific device behaviors
* Summary statistics describing numerical data properties, e.g. sum, average, mininum and maximum 
* Cardinality (unique) counts of a given value 

Tons of great observables can be extracted from Zeek's Conn events alone, in fact, Netbase currently includes 52 of them (visible in the flow module).  It also includes other protocol-specific observables that can be found in their respective modules.   

# Monitored Hosts 

Netbase generates observations for _monitored_ hosts, or hosts the user is specifically concerned with.  In smaller networks it might be practical to apply this methodology to all hosts, but in larger networks its usually prudent to refine things a bit.  

By default, Netbase considers any IP address that belongs to a subnet defined in Zeek's `Site::local_nets` variable a _monitored_ host.  This is customizable using the `Netbase::monitoring_mode` variable (default = LOCAL_NETS).  Other monitoring mode options include:

* PRIVATE_NETS - Record observations for any IP within a non-routable RFC 1918 address range
* LOCAL_AND_NEIGHBORS - Record observations for any IP within a Site:local_nets or Site::local_neighbors subnets

In addition, or alternatively, you can define specific subnets that contain _monitored_ hosts using the `Netbase::critical_assets` variable.  Any IP address belonging to a subnet defined in `Netbase::critical_assets` will always be monitored, regardless of the monitoring mode selected.  

# Analyzing Netbase Observations 

There are many ways to work with data generated by Netbase.  Here a few of the most useful approaches:

* Compare new observations for a specific IP to its own historical observations
* Compare new observations for a given IP to historical observations for other, similar hosts
* Compare observations for all monitored hosts at once 
* Compare observations across other categorical dimensions such as OS, service, function and location
