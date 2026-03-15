#!/bin/bash
echo "==FTRACE COOKER=="

function echol(){
    echo "";
    echo "$@";
}

sudo trace-cmd stat


cd /sys/kernel/tracing
current=$(cat current_tracer)
echol "Current tracer: $current"
if [ $(cat current_tracer) = "nop" ]; then
    echo "nop is safe!";
else
    echo "$current is not safe!!!!!";
fi

echol "Turning off writing to ftrace ring buffer..."
echo "0" > tracing_on
echo "Turned off!"

echol "All functions that have been ftraced (/sys/kernel/tracing/touched_functions):"
cat touched_functions

echol "All functions enabled for ftracing / functions with callbacks (/sys/kernel/tracing/enabled_functions):"
cat enabled_functions

echol "If the results said current tracer is nop and enabled_functions had nothing, then you're good!"
echo "If enabled_functions has something, look at it to see what type of function it is. It could be fine (like bpf_lsm_file_open)"
echo 'Otherwise, if there are tracers running or enabled, this is bad!! Instead of killing it right now, record data for IR report!'
echo 'To do so, use trace-cmd. Use arguments record/profile/hist/stat/extract/show to collect data. When ready to clear, run: sudo su; echo 'nop' > /sys/kernel/tracing/tracer; trace-cmd reset'

# echo "nop" > current_tracer;
# echo "Switched!"