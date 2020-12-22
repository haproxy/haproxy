/*
 * QPACK header table management (draft-ietf-quic-qpack-20)
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <import/ist.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/qpack-tbl-t.h>

/* static header table as in draft-ietf-quic-qpack-20 Appendix A. [0] unused. */
const struct http_hdr qpack_sht[QPACK_SHT_SIZE] = {
	[ 0] = { .n = IST(":authority"),                       .v = IST("")                         },
	[ 1] = { .n = IST(":path"),                            .v = IST("/")                        },
	[ 2] = { .n = IST("age"),                              .v = IST("0")                        },
	[ 3] = { .n = IST("content-disposition"),              .v = IST("")                         },
	[ 4] = { .n = IST("content-length"),                   .v = IST("0")                        },
	[ 5] = { .n = IST("cookie"),                           .v = IST("")                         },
	[ 6] = { .n = IST("date"),                             .v = IST("")                         },
	[ 7] = { .n = IST("etag"),                             .v = IST("")                         },
	[ 8] = { .n = IST("if-modified-since"),                .v = IST("")                         },
	[ 9] = { .n = IST("if-none-match"),                    .v = IST("")                         },
	[10] = { .n = IST("last-modified"),                    .v = IST("")                         },
	[11] = { .n = IST("link"),                             .v = IST("")                         },
	[12] = { .n = IST("location"),                         .v = IST("")                         },
	[13] = { .n = IST("referer"),                          .v = IST("")                         },
	[14] = { .n = IST("set-cookie"),                       .v = IST("")                         },
	[15] = { .n = IST(":method"),                          .v = IST("CONNECT")                  },
	[16] = { .n = IST(":method"),                          .v = IST("DELETE")                   },
	[17] = { .n = IST(":method"),                          .v = IST("GET")                      },
	[18] = { .n = IST(":method"),                          .v = IST("HEAD")                     },
	[19] = { .n = IST(":method"),                          .v = IST("OPTIONS")                  },
	[20] = { .n = IST(":method"),                          .v = IST("POST")                     },
	[21] = { .n = IST(":method"),                          .v = IST("PUT")                      },
	[22] = { .n = IST(":scheme"),                          .v = IST("http")                     },
	[23] = { .n = IST(":scheme"),                          .v = IST("https")                    },
	[24] = { .n = IST(":status"),                          .v = IST("103")                      },
	[25] = { .n = IST(":status"),                          .v = IST("200")                      },
	[26] = { .n = IST(":status"),                          .v = IST("304")                      },
	[27] = { .n = IST(":status"),                          .v = IST("404")                      },
	[28] = { .n = IST(":status"),                          .v = IST("503")                      },
	[29] = { .n = IST("accept"),                           .v = IST("*/*")                      },
	[30] = { .n = IST("accept"),                           .v = IST("application/dns-message")  },
	[31] = { .n = IST("accept-encoding"),                  .v = IST("gzip, deflate, br")        },
	[32] = { .n = IST("accept-ranges"),                    .v = IST("bytes")                    },
	[33] = { .n = IST("access-control-allow-headers"),     .v = IST("cache-control")            },
	[34] = { .n = IST("access-control-allow-headers"),     .v = IST("content-type")             },
	[35] = { .n = IST("access-control-allow-origin"),      .v = IST("*")                        },
	[36] = { .n = IST("cache-control"),                    .v = IST("max-age=0")                },
	[37] = { .n = IST("cache-control"),                    .v = IST("max-age=2592000")          },
	[38] = { .n = IST("cache-control"),                    .v = IST("max-age=604800")           },
	[39] = { .n = IST("cache-control"),                    .v = IST("no-cache")                 },
	[40] = { .n = IST("cache-control"),                    .v = IST("no-store")                 },
	[41] = { .n = IST("cache-control"),                    .v = IST("public, max-age=31536000") },
	[42] = { .n = IST("content-encoding"),                 .v = IST("br")                       },
	[43] = { .n = IST("content-encoding"),                 .v = IST("gzip")                     },
	[44] = { .n = IST("content-type"),                     .v = IST("application/dns-message")  },
	[45] = { .n = IST("content-type"),                     .v = IST("application/javascript")   },
	[46] = { .n = IST("content-type"),                     .v = IST("application/json")         },
	[47] = { .n = IST("content-type"),                     .v = IST("application/"
	                                                                "x-www-form-urlencoded")    },
	[48] = { .n = IST("content-type"),                     .v = IST("image/gif")                },
	[49] = { .n = IST("content-type"),                     .v = IST("image/jpeg")               },
	[50] = { .n = IST("content-type"),                     .v = IST("image/png")                },
	[51] = { .n = IST("content-type"),                     .v = IST("text/css")                 },
	[52] = { .n = IST("content-type"),                     .v = IST("text/html;"
	                                                                " charset=utf-8")           },
	[53] = { .n = IST("content-type"),                     .v = IST("text/plain")               },
	[54] = { .n = IST("content-type"),                     .v = IST("text/plain;"
	                                                                "charset=utf-8")            },
	[55] = { .n = IST("range"),                            .v = IST("bytes=0-")                 },
	[56] = { .n = IST("strict-transport-security"),        .v = IST("max-age=31536000")         },
	[57] = { .n = IST("strict-transport-security"),        .v = IST("max-age=31536000;"
	                                                                " includesubdomains")       },
	[58] = { .n = IST("strict-transport-security"),        .v = IST("max-age=31536000;"
	                                                                " includesubdomains;"
	                                                                " preload")                 },
	[59] = { .n = IST("vary"),                             .v = IST("accept-encoding")          },
	[60] = { .n = IST("vary"),                             .v = IST("origin")                   },
	[61] = { .n = IST("x-content-type-options"),           .v = IST("nosniff")                  },
	[62] = { .n = IST("x-xss-protection"),                 .v = IST("1; mode=block")            },
	[63] = { .n = IST(":status"),                          .v = IST("100")                      },
	[64] = { .n = IST(":status"),                          .v = IST("204")                      },
	[65] = { .n = IST(":status"),                          .v = IST("206")                      },
	[66] = { .n = IST(":status"),                          .v = IST("302")                      },
	[67] = { .n = IST(":status"),                          .v = IST("400")                      },
	[68] = { .n = IST(":status"),                          .v = IST("403")                      },
	[69] = { .n = IST(":status"),                          .v = IST("421")                      },
	[70] = { .n = IST(":status"),                          .v = IST("425")                      },
	[71] = { .n = IST(":status"),                          .v = IST("500")                      },
	[72] = { .n = IST("accept-language"),                  .v = IST("")                         },
	[73] = { .n = IST("access-control-allow-credentials"), .v = IST("FALSE")                    },
	[74] = { .n = IST("access-control-allow-credentials"), .v = IST("TRUE")                     },
	[75] = { .n = IST("access-control-allow-headers"),     .v = IST("*")                        },
	[76] = { .n = IST("access-control-allow-methods"),     .v = IST("get")                      },
	[77] = { .n = IST("access-control-allow-methods"),     .v = IST("get, post, options")       },
	[78] = { .n = IST("access-control-allow-methods"),     .v = IST("options")                  },
	[79] = { .n = IST("access-control-expose-headers"),    .v = IST("content-length")           },
	[80] = { .n = IST("access-control-request-headers"),   .v = IST("content-type")             },
	[81] = { .n = IST("access-control-request-method"),    .v = IST("get")                      },
	[82] = { .n = IST("access-control-request-method"),    .v = IST("post")                     },
	[83] = { .n = IST("alt-svc"),                          .v = IST("clear")                    },
	[84] = { .n = IST("authorization"),                    .v = IST("")                         },
	[85] = { .n = IST("content-security-policy"),          .v = IST("script-src 'none';"
	                                                                " object-src 'none';"
	                                                                " base-uri 'none'")         },
	[86] = { .n = IST("early-data"),                       .v = IST("1")                        },
	[87] = { .n = IST("expect-ct"),                        .v = IST("")                         },
	[88] = { .n = IST("forwarded"),                        .v = IST("")                         },
	[89] = { .n = IST("if-range"),                         .v = IST("")                         },
	[90] = { .n = IST("origin"),                           .v = IST("")                         },
	[91] = { .n = IST("purpose"),                          .v = IST("prefetch")                 },
	[92] = { .n = IST("server"),                           .v = IST("")                         },
	[93] = { .n = IST("timing-allow-origin"),              .v = IST("*")                        },
	[94] = { .n = IST("upgrade-insecure-requests"),        .v = IST("1")                        },
	[95] = { .n = IST("user-agent"),                       .v = IST("")                         },
	[96] = { .n = IST("x-forwarded-for"),                  .v = IST("")                         },
	[97] = { .n = IST("x-frame-options"),                  .v = IST("deny")                     },
	[98] = { .n = IST("x-frame-options"),                  .v = IST("sameorigin")               },
};

