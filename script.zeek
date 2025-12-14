@load base/protocols/conn
@load base/protocols/mqtt/main
@load base/frameworks/logging

module C2_Fuzzy;

export {
    type SignalRecord: record {
        ts: time         &log;
        uid: string      &log;
        id: conn_id      &log;
        category: string &log; 
        details: string  &log;
    };

    redef enum Log::ID += { LOG_C2_FUZZY };

    # Heuristics - Tunable
    const min_inter_arrival: interval = 0.5secs &redef; 
    const max_unique_keys: count = 3 &redef;            
}

type C2State: record {
    last_pub_ts: time;
    observed_qos: set[count];     
    observed_keys: set[string];   
    last_delta: interval;         
};

global state_tracker: table[addr] of C2State &read_expire=5mins;

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

# FIX: Updated signature to match standard Zeek MQTT analyzer
event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg)
    {
    local orig = c$id$orig_h;
    
    if ( orig !in state_tracker )
        {
        # FIX: Explicit initialization to avoid "Type Clash" with set()
        local new_state: C2State;
        new_state$last_pub_ts = network_time();
        new_state$observed_qos = set();
        new_state$observed_keys = set();
        new_state$last_delta = 0secs;
        
        state_tracker[orig] = new_state;
        }

    local now = network_time();
    local delta = now - state_tracker[orig]$last_pub_ts;
    state_tracker[orig]$last_pub_ts = now;

    if ( delta > min_inter_arrival )
        {
        local prev = state_tracker[orig]$last_delta;
        
        if ( prev > 0.1secs )
            {
            local ratio = (delta > prev) ? (delta / prev) : (prev / delta);
            
            if ( ratio > 1.5 && ratio < 10.0 )
                {
                # Note: Using msg$topic or msg$payload is possible here if needed
                log_fuzzy(c, "timing-pattern", fmt("Interval switched from %.1fs to %.1fs (Ratio: %.1f)", 
                          interval_to_double(prev), interval_to_double(delta), ratio));
                }
            }
        state_tracker[orig]$last_delta = delta;
        }
    }

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

event mqtt_user_property(c: connection, is_orig: bool, msg_id: count, key: string, value: string)
    {
    local orig = c$id$orig_h;

    if ( orig in state_tracker )
        {
        local known_keys = state_tracker[orig]$observed_keys;
        
        if ( key !in known_keys )
            {
            add state_tracker[orig]$observed_keys[key];
            
            if ( |state_tracker[orig]$observed_keys| >= 2 ) 
                {
                log_fuzzy(c, "metadata-churn", fmt("Device rotating keys. New key: '%s'. Count: %d", 
                          key, |state_tracker[orig]$observed_keys|));
                }
            }
            
        if ( |value| <= 1 )
            {
             log_fuzzy(c, "metadata-value", fmt("Suspect low-entropy value in metadata key '%s': '%s'", key, value));
            }
        }
    }