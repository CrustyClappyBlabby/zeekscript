@load base/protocols/conn
@load base/protocols/mqtt/main
@load base/frameworks/logging

module C2_Fuzzy;

export {
    type SignalRecord: record {
        ts: time         &log;
        uid: string      &log;
        id: conn_id      &log;
        category: string &log; # "qos-instability", "metadata-churn", "timing-pattern"
        details: string  &log;
    };

    redef enum Log::ID += { LOG_C2_FUZZY };

    # Heuristics - Tunable
    const min_inter_arrival: interval = 0.5secs &redef; # Ignore rapid bursts
    const max_unique_keys: count = 3 &redef;            # How many unique keys before we suspect churn?
}

# Track state per source IP
type C2State: record {
    last_pub_ts: time;
    observed_qos: set[count];     # Track all seen QoS levels
    observed_keys: set[string];   # Track all seen Property Keys
    last_delta: interval;         # To compare previous timing interval
};

global state_tracker: table[addr] of C2State;

event zeek_init()
    {
    Log::create_stream(C2_Fuzzy::LOG_C2_FUZZY,
        [$columns = SignalRecord, $path = "c2_fuzzy"]);
    }

function log_fuzzy(c: connection, cat: string, det: string)
    {
    Log::write(C2_Fuzzy::LOG_C2_FUZZY, [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id,
        $category = cat,
        $details = det
    ]);
    }

############################################################
# 1. QoS INSTABILITY
# Detects any device that can't decide on a single QoS level
############################################################

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, topic: string, payload: string)
    {
    local orig = c$id$orig_h;
    local current_qos = 0; # Default assumption if unknown, usually extracted from flags if available
    
    # Initialize state if new
    if ( orig !in state_tracker )
        state_tracker[orig] = [
            $last_pub_ts=network_time(), 
            $observed_qos=set(), 
            $observed_keys=set(),
            $last_delta=0secs
        ];

    # Note: In standard Zeek MQTT, we often infer QoS from handshake or msg_id presence.
    # We will refine this in the specific QoS events below.
    
    # --- TIMING ANALYSIS (Generic) ---
    local now = network_time();
    local delta = now - state_tracker[orig]$last_pub_ts;
    state_tracker[orig]$last_pub_ts = now;

    if ( delta > min_inter_arrival )
        {
        local prev = state_tracker[orig]$last_delta;
        
        # Check for significant distinct shifts in timing (e.g. 2s vs 5s)
        # We look for a ratio difference > 1.5 to indicate a "mode switch" rather than jitter
        if ( prev > 0.1secs )
            {
            local ratio = (delta > prev) ? (delta / prev) : (prev / delta);
            
            # If the timing jumped significantly (but is still a regular interval pattern)
            if ( ratio > 1.5 && ratio < 10.0 )
                {
                log_fuzzy(c, "timing-pattern", fmt("Interval switched from %.1fs to %.1fs (Ratio: %.1f)", 
                          interval_to_double(prev), interval_to_double(delta), ratio));
                }
            }
        state_tracker[orig]$last_delta = delta;
        }
    }

# Update QoS sets based on ACKs (QoS 1) and COMPs (QoS 2)
event mqtt_puback(c: connection, is_orig: bool, msg_id: count)
    {
    if ( c$id$orig_h in state_tracker )
        {
        add state_tracker[c$id$orig_h]$observed_qos[1];
        if ( |state_tracker[c$id$orig_h]$observed_qos| > 1 )
            log_fuzzy(c, "qos-instability", "Device using multiple QoS levels (seen QoS 1)");
        }
    }

event mqtt_pubcomp(c: connection, is_orig: bool, msg_id: count)
    {
    if ( c$id$orig_h in state_tracker )
        {
        add state_tracker[c$id$orig_h]$observed_qos[2];
        if ( |state_tracker[c$id$orig_h]$observed_qos| > 1 )
            log_fuzzy(c, "qos-instability", "Device using multiple QoS levels (seen QoS 2)");
        }
    }

############################################################
# 2. METADATA CHURN
# Detects devices that rotate through different property keys
############################################################

event mqtt_user_property(c: connection, is_orig: bool, msg_id: count, key: string, value: string)
    {
    local orig = c$id$orig_h;

    if ( orig in state_tracker )
        {
        local known_keys = state_tracker[orig]$observed_keys;
        
        if ( key !in known_keys )
            {
            add state_tracker[orig]$observed_keys[key];
            
            # If a single device uses too many distinct keys, or specific pairs
            if ( |state_tracker[orig]$observed_keys| >= 2 ) 
                {
                # Check if the keys look like "alternatives" (heuristic: same length, common substrings)
                # This catches trace_id vs span_id without hardcoding them
                log_fuzzy(c, "metadata-churn", fmt("Device rotating keys. New key: '%s'. Count: %d", 
                          key, |state_tracker[orig]$observed_keys|));
                }
            }
            
        # Optional: Detect Low Entropy Values (like "0", "1", "true") in metadata
        if ( |value| <= 1 )
            {
             log_fuzzy(c, "metadata-value", fmt("Suspect low-entropy value in metadata key '%s': '%s'", key, value));
            }
        }
    }