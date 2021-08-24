#ifndef QPACK_ENC_H_
#define QPACK_ENC_H_

#include <haproxy/istbuf.h>

struct buffer;

int qpack_encode_field_section_line(struct buffer *out);
int qpack_encode_int_status(struct buffer *out, unsigned int status);
int qpack_encode_header(struct buffer *out, const struct ist n, const struct ist v);

#endif /* QPACK_ENC_H_ */
