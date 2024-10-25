#ifndef _HAPROXY_QUIC_PACING_H
#define _HAPROXY_QUIC_PACING_H

#include <haproxy/quic_pacing-t.h>

#include <haproxy/list.h>
#include <haproxy/quic_frame.h>

static inline void quic_pacing_init(struct quic_pacer *pacer,
                                    const struct quic_cc_path *path)
{
	LIST_INIT(&pacer->frms);
	pacer->path = path;
}

static inline void quic_pacing_reset(struct quic_pacer *pacer)
{
	struct quic_frame *frm;

	while (!LIST_ISEMPTY(&pacer->frms)) {
		frm = LIST_ELEM(pacer->frms.n, struct quic_frame *, list);
		/* qc_frm_free is responsible to detach frm from pacer list. */
		qc_frm_free(NULL, &frm);
	}
}

static inline struct list *quic_pacing_frms(struct quic_pacer *pacer)
{
	return &pacer->frms;
}

#endif /* _HAPROXY_QUIC_PACING_H */
