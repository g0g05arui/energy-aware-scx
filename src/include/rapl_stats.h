#ifndef RAPL_STATS_H
#define RAPL_STATS_H

#define energy_t unsigned long long
#define power_t unsigned long long
#define time_t_ns unsigned long long
#define MAX_CORE_SENSORS 64

struct rapl_stats{
    // Power consumption (in watts)
    power_t package_power;       // Total package power
    power_t core_power;          // CPU cores power
    
    energy_t package_energy;     // Total package energy consumed
    energy_t core_energy;        // CPU cores energy consumed
    
    // Temperature (in degrees Celsius)
    unsigned int package_temp;   // Package temperature
    unsigned int core_temp[MAX_CORE_SENSORS]; // Per-core temperatures
    unsigned int core_count;     // Number of cores represented
    
    time_t_ns timestamp;         // Time of measurement
    time_t_ns delta_time;        // Time elapsed since last measurement
    
    power_t tdp;                 
};

struct rapl_config{
    unsigned int core_count;
};

#endif
