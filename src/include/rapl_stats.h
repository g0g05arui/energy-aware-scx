#ifndef RAPL_STATS_H
#define RAPL_STATS_H

#if defined(__has_include)
#  if __has_include("temp_thresholds.h")
#    include "temp_thresholds.h"
#  endif
#endif

#ifndef TEMP_THRESHOLD_WARM
#define TEMP_THRESHOLD_WARM 55
#endif

#ifndef TEMP_THRESHOLD_HOT
#define TEMP_THRESHOLD_HOT 60
#endif

#ifndef TEMP_THRESHOLD_THROTTLE
#define TEMP_THRESHOLD_THROTTLE 85
#endif

#define energy_t unsigned long long
#define power_t unsigned long long
#define time_t_ns unsigned long long
#define MAX_CORE_TEMPS 64
#define MAX_CPUS 256

struct rapl_stats{
    power_t package_power;      
    power_t core_power;          
    
    energy_t package_energy;    
    energy_t core_energy;      
    
    unsigned int package_temp;   
    unsigned int core_count;     
    
    time_t_ns timestamp;    
    time_t_ns delta_time;  
    
    power_t tdp;                 
};

struct rapl_config{
    unsigned int core_count;
    unsigned int tjmax_cpu_count;
};

struct tjmax_delta_sample {
    unsigned int delta;
    time_t_ns ts_ns;
};

#endif
