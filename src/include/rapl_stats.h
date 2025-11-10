#ifndef RAPL_STATS_H
#define RAPL_STATS_H

#define energy_t unsigned long long
#define power_t unsigned long long
#define time_t_ns unsigned long long
#define MAX_CORE_TEMPS 64

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
};

#endif
