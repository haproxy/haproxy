#ifndef _HAPROXY_STRESS_H
#define _HAPROXY_STRESS_H

#ifdef DEBUG_STRESS
enum { mode_stress = 1 };
#else
enum { mode_stress = 0 };
#endif

extern int mode_stress_level;

#define STRESS_RUN1(a,b) (mode_stress && unlikely(mode_stress_level >= 1) ? (a) : (b))
#define STRESS_RUN2(a,b) (mode_stress && unlikely(mode_stress_level >= 2) ? (a) : (b))
#define STRESS_RUN3(a,b) (mode_stress && unlikely(mode_stress_level >= 3) ? (a) : (b))
#define STRESS_RUN4(a,b) (mode_stress && unlikely(mode_stress_level >= 4) ? (a) : (b))
#define STRESS_RUN5(a,b) (mode_stress && unlikely(mode_stress_level >= 5) ? (a) : (b))
#define STRESS_RUN6(a,b) (mode_stress && unlikely(mode_stress_level >= 6) ? (a) : (b))
#define STRESS_RUN7(a,b) (mode_stress && unlikely(mode_stress_level >= 7) ? (a) : (b))
#define STRESS_RUN8(a,b) (mode_stress && unlikely(mode_stress_level >= 8) ? (a) : (b))
#define STRESS_RUN9(a,b) (mode_stress && unlikely(mode_stress_level >= 9) ? (a) : (b))

#endif /* _HAPROXY_STRESS_H */
