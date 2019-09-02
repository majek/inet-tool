struct addr {
	uint32_t prefixlen;
	uint8_t protocol;
	uint16_t port;
	struct ip {
		uint32_t ip_as_w[4];
	} addr;
};

struct srvname {
	char name[32];
};

enum { REDIR_MAP,
       BIND_MAP,
       SRVNAME_MAP,
};
