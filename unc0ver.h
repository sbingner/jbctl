#ifndef _UNC0VER_OPTIONS
#define _UNC0VER_OPTIONS

#define OPT(x) (offset_options?((rk64(offset_options) & OPT_ ##x)?true:false):false)
#define SETOPT(x, val) (offset_options?wk64(offset_options, val?(rk64(offset_options) | OPT_ ##x):(rk64(offset_options) & ~OPT_ ##x)):0)
#define OPT_GET_TASK_ALLOW (1<<0)
#define OPT_CS_DEBUGGED (1<<1)

#endif
