/* GPIO numbers for each signal. Negative values are invalid */
// #define tck_gpio 8
// #define tms_gpio 0
// #define tdi_gpio 0
// #define tdo_gpio 8
// #define led      18

/* Statuses */
#define RUNNING 1
#define STOP    2
#define STOPPED 0

/* Exposed functions: */
int start(int port);
void stop();