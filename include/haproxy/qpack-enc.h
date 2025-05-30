#ifndef QPACK_ENC_H_
#define QPACK_ENC_H_

#include <haproxy/http-t.h>
#include <haproxy/istbuf.h>

struct buffer;

int qpack_encode_field_section_line(struct buffer *out);
int qpack_encode_int_status(struct buffer *out, unsigned int status);
int qpack_encode_method(struct buffer *out, enum http_meth_t meth, struct ist other);
int qpack_encode_scheme(struct buffer *out, const struct ist scheme);
int qpack_encode_path(struct buffer *out, const struct ist path);
int qpack_encode_auth(struct buffer *out, const struct ist auth);
int qpack_encode_header(struct buffer *out, const struct ist n, const struct ist v);

#endif /* QPACK_ENC_H_ */
