# include <kernel/kernel.h>
# include <kernel/user.h>

inherit conn LIB_CONN;
inherit user LIB_USER;

# define DEBUG(mesg)	DRIVER->message("SSH: " + (mesg) + "\n")

# define SSH_MSG_DISCONNECT			1
# define SSH_MSG_IGNORE				2
# define SSH_MSG_UNIMPLEMENTED			3
# define SSH_MSG_DEBUG				4
# define SSH_MSG_SERVICE_REQUEST		5
# define SSH_MSG_SERVICE_ACCEPT			6
# define SSH_MSG_KEXINIT			20
# define SSH_MSG_NEWKEYS			21
# define SSH_MSG_KEXDH_INIT			30
# define SSH_MSG_KEXDH_REPLY			31
# define SSH_MSG_USERAUTH_REQUEST		50
# define SSH_MSG_USERAUTH_FAILURE		51
# define SSH_MSG_USERAUTH_SUCCESS		52
# define SSH_MSG_USERAUTH_BANNER		53
# define SSH_MSG_GLOBAL_REQUEST			80
# define SSH_MSG_REQUEST_SUCCESS		81
# define SSH_MSG_REQUEST_FAILURE		82
# define SSH_MSG_CHANNEL_OPEN			90
# define SSH_MSG_CHANNEL_OPEN_CONFIRMATION	91
# define SSH_MSG_CHANNEL_OPEN_FAILURE		92
# define SSH_MSG_CHANNEL_WINDOW_ADJUST		93
# define SSH_MSG_CHANNEL_DATA			94
# define SSH_MSG_CHANNEL_EXTENDED_DATA		95
# define SSH_MSG_CHANNEL_EOF			96
# define SSH_MSG_CHANNEL_CLOSE			97
# define SSH_MSG_CHANNEL_REQUEST		98
# define SSH_MSG_CHANNEL_SUCCESS		99
# define SSH_MSG_CHANNEL_FAILURE		100

# define SSH_DISCONNECT_PROTOCOL_ERROR		2
# define SSH_DISCONNECT_MAC_ERROR		5
# define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE	7

# define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED	1
# define SSH_OPEN_CONNECT_FAILED		2
# define SSH_OPEN_UNKNOWN_CHANNEL_TYPE		3
# define SSH_OPEN_RESOURCE_SHORTAGE		4


private int receive_packet(string str);
private int userauth(string str);
private int client(string str);


/* ========================================================================= *
 *			    Section 1: packet layer			     *
 * ========================================================================= */

private string buffer;			/* received so far */
private string header;			/* first 8 characters of packet */
private int length;			/* length of packet to receive */
private int recv_seqno, send_seqno;	/* send and receive sequence numbers */
private string dkey1, dkey2, dkey3;	/* decryption keys */
private string ekey1, ekey2, ekey3;	/* encryption keys */
private string dstate, estate;		/* en/decryption state */
private string client_mac;		/* client MAC key */
private string server_mac;		/* server MAC key */
private string session_id;		/* ID for this entire session */

/*
 * NAME:	random_string()
 * DESCRIPTION:	create a string of pseudo-random bytes
 */
private string random_string(int length)
{
    string str;
    int n, rand;

    str = "................................";
    while (strlen(str) < length) {
	str += str;
    }
    str = str[.. length - 1];
    for (n = length & ~1; n != 0; ) {
	/* create two random bytes at a time */
	rand = random(65536);
	str[--n] = rand >> 8;
	str[--n] = rand;
    }
    if (length & 1) {
	str[length - 1] = random(256);
    }

    return str;
}

/*
 * NAME:	make_int()
 * DESCRIPTION:	build a SSH int
 */
private string make_int(int i)
{
    string str;

    str = "....";
    str[0] = i >> 24;
    str[1] = i >> 16;
    str[2] = i >> 8;
    str[3] = i;

    return str;
}

/*
 * NAME:	make_string()
 * DESCRIPTION:	build a SSH string
 */
private string make_string(string str)
{
    string header;
    int length;

    length = strlen(str);
    header = "\0\0..";
    header[2] = length >> 8;
    header[3] = length;

    return header + str;
}

/*
 * NAME:	make_mesg()
 * DESCRIPTION:	create a message code
 */
private string make_mesg(int code)
{
    string str;

    str = ".";
    str[0] = code;
    return str;
}

/*
 * NAME:	make_packet()
 * DESCRIPTION:	build a packet (without MAC)
 */
private string make_packet(string str)
{
    int length, padding;

    /* minimum padding is 4 bytes, round up to multiple of 8 bytes */
    length = strlen(str);
    padding = 12 - (length + 1) % 8;
    length += padding + 1;

    str = "\0\0..." + str + random_string(padding);
    str[2] = length >> 8;
    str[3] = length;
    str[4] = padding;

    return str;
}

/*
 * NAME:	get_int()
 * DESCRIPTION:	get an int from a buffer
 */
private int get_int(string b, int i)
{
    return (b[i] << 24) + (b[i + 1] << 16) + (b[i + 2] << 8) + b[i + 3];
}

/*
 * NAME:	get_string()
 * DESCRIPTION:	get a string from a buffer
 */
private string get_string(string b, int i)
{
    return b[i + 4 .. i + (b[i] << 24) + (b[i + 1] << 16) + (b[i + 2] << 8) +
		      b[i + 3] + 3];
}

/*
 * NAME:	encrypt_packet()
 * DESCRIPTION:	encrypt a packet
 */
private string encrypt_packet(string str)
{
    int i, n, length;
    string *encrypted;

    length = strlen(str);
    encrypted = allocate(length / 8);
    for (i = n = 0; i < length; i += 8, n++) {
	estate = encrypt("DES",
			 decrypt("DES",
				 encrypt("DES",
					 asn_xor(str[i .. i + 7], estate),
					 ekey1),
				 ekey2),
			 ekey3);
	encrypted[n] = estate;
    }
    return implode(encrypted, "");
}

/*
 * NAME:	decrypt_string()
 * DESCRIPTION:	decrypt a string
 */
private string decrypt_string(string str)
{
    int i, n, length;
    string chunk, *decrypted;

    length = strlen(str);
    decrypted = allocate(length / 8);
    for (i = n = 0; i < length; i += 8, n++) {
	chunk = str[i .. i + 7];
	decrypted[n] = asn_xor(decrypt("DES",
				       encrypt("DES",
					       decrypt("DES", chunk, dkey3),
					       dkey2),
				       dkey1),
			       dstate);
	dstate = chunk;
    }
    return implode(decrypted, "");
}

/*
 * NAME:	hmac()
 * DESCRIPTION:	compute HMAC
 */
private string hmac(string key, string str)
{
    string ipad, opad;

    ipad = "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36" +
	   "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36" +
	   "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36" +
	   "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36";
    opad = "\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c" +
	   "\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c" +
	   "\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c" +
	   "\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c";
    return hash_sha1(asn_xor(key, opad), hash_sha1(asn_xor(key, ipad), str));
}

/*
 * NAME:	send_packet()
 * DESCRIPTION:	send a packet to the other side
 */
private int send_packet(string str)
{
    str = make_packet(str);
    if (server_mac) {
	str = encrypt_packet(str) +
	      hmac(server_mac, make_int(send_seqno) + str);
    }
    send_seqno++;
    return user::message(str);
}

/*
 * NAME:	process_message()
 * DESCRIPTION:	process a message
 */
static int process_message(string str)
{
    if (client_mac) {
	string mac;

	/* decrypt & verify MAC */
	mac = str[length ..];
	str = header + decrypt_string(str[.. length - 1]);
	if (mac != hmac(client_mac, make_int(recv_seqno) + str)) {
	    DEBUG("bad MAC");
	    send_packet(make_mesg(SSH_MSG_DISCONNECT) +
			make_int(SSH_DISCONNECT_MAC_ERROR) +
			make_string("bad MAC") +
			make_string("en"));
	    return MODE_DISCONNECT;
	}
    } else {
	/* unencrypted */
	str = header + str;
    }
    recv_seqno++;

    str = str[5 .. length + 7 - str[4]];
    length = -1;
    return receive_packet(str);
}

/*
 * NAME:	receive_message()
 * DESCRIPTION:	receive a message
 */
int receive_message(string str)
{
    int mode;

    if (previous_program() == LIB_CONN) {
	buffer += str;
	while (query_conn()) {
	    if (length < 0) {
		/*
		 * new packet
		 */
		if (strlen(buffer) < 8) {
		    break;
		}
		header = buffer[.. 7];
		buffer = buffer[8 ..];
		if (client_mac) {
		    header = decrypt_string(header);
		}
		length = get_int(header, 0);
		if (length <= 0 || length > 35000 - 4 || (length & 7) != 4) {
		    DEBUG("bad packet length " + length);
		    send_packet(make_mesg(SSH_MSG_DISCONNECT) +
				make_int(SSH_DISCONNECT_PROTOCOL_ERROR) +
				make_string("bad packet length") +
				make_string("en"));
		    return MODE_DISCONNECT;
		}
		length -= 4;
		if (client_mac) {
		    length += 20;
		}
	    }

	    if (strlen(buffer) < length) {
		break;
	    }

	    /*
	     * full packet received
	     */
	    str = buffer[.. length - 1];
	    buffer = buffer[length ..];
	    if (client_mac) {
		length -= 20;
	    }
	    mode = call_limited("process_message", str);
	    if (mode == MODE_DISCONNECT) {
		return MODE_DISCONNECT;
	    }
	    if (mode >= MODE_UNBLOCK) {
		query_conn()->set_mode(mode);
	    }
	}
    }
    return MODE_RAW;
}

/*
 * NAME:	create_packet()
 * DESCRIPTION:	initialize packet layer functions
 */
private void create_packet()
{
    buffer = "";
    length = -1;
}


/* ========================================================================= *
 *			    Section 2: transport layer			     *
 * ========================================================================= */

# define SSHD	"/usr/System/sys/sshd"

# define TRANSPORT_KEXINIT	0
# define TRANSPORT_SKIP		1
# define TRANSPORT_KEXDH	2
# define TRANSPORT_NEWKEYS	3
# define TRANSPORT_TRANSPORT	4


private int transport_state;	/* transport state */
private string client_version;	/* client protocol version string */
private string client_kexinit;	/* client KEXINIT string */
private string server_kexinit;	/* server KEXINIT string */
private string p, q;		/* prime and group order */
private string y;		/* intermediate result */
private string f, e;		/* shared secrets */
private string K, H;		/* crypto stuff */

/*
 * NAME:	asn1_scan_int()
 * DESCRIPTION:	look for the next int in an ASN.1/DER encoded string
 */
private int asn1_scan_int(string str, int offset)
{
    int tag, length, size;

    for (;;) {
	tag = str[offset++] & 0x1f;
	if (tag == 0x1f) {
	    /* ignore multi-octet identifier */
	    while (str[offset++] & 0x80) ;
	}

	length = str[offset++];
	if (length & 0x80) {
	    /* multi-octet length */
	    size = length & 0x7f;
	    length = 0;
	    while (size != 0) {
		length = (length << 8) + str[offset++];
		--size;
	    }
	}

	switch (tag) {
	case 2:		/* int */
	    return (length << 16) + offset;

	case 16:	/* sequence */
	    break;

	default:	/* anything else */
	    offset += length;
	    break;
	}
    }
}

/*
 * NAME:	better_random_string()
 * DESCRIPTION:	create a slightly more random string
 */
private string better_random_string(int length)
{
    string str;

    str = "";
    while (length >= 20) {
	str += hash_sha1(random_string(20));
	length -= 20;
    }
    if (length >= 0) {
	str += hash_sha1(random_string(length))[.. length - 1];
    }

    return str;
}

/*
 * NAME:	ssh_dss_sign()
 * DESCRIPTION:	sign m with the host key
 */
private string ssh_dss_sign(string m, string host_key)
{
    int offset, length;
    string p, q, g, x;
    string k, r, s;

    /* retrieve params from key */
    offset = asn1_scan_int(host_key, 0);
    length = offset >> 16; offset &= 0xffff;
    offset = asn1_scan_int(host_key, offset + length);
    length = offset >> 16; offset &= 0xffff;
    p = host_key[offset .. offset + length - 1];
    offset = asn1_scan_int(host_key, offset + length);
    length = offset >> 16; offset &= 0xffff;
    q = host_key[offset .. offset + length - 1];
    offset = asn1_scan_int(host_key, offset + length);
    length = offset >> 16; offset &= 0xffff;
    g = host_key[offset .. offset + length - 1];
    offset = asn1_scan_int(host_key, offset + length);
    length = offset >> 16; offset &= 0xffff;
    offset = asn1_scan_int(host_key, offset + length);
    length = offset >> 16; offset &= 0xffff;
    x = host_key[offset .. offset + length - 1];

    /* k = random 0 < k < q */
    do {
	k = asn_mod("\1" + better_random_string(strlen(q)), q);
    } while (strlen(k) < strlen(q) - 1);

    /* r = (g ^ k mod p) mod q */
    r = asn_mod(asn_pow(g, k, p), q);

    /* s = (k ^ -1 * (H(m) + x * r)) mod q */
    s = asn_mult(asn_pow(k, asn_sub(q, "\2", q), q),
		 asn_add("\0" + hash_sha1(m), asn_mult(x, r, q), q),
		 q);

    r = ("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" + r)[strlen(r) ..];
    s = ("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" + s)[strlen(s) ..];
    return make_string("ssh-dss") + make_string(r + s);
}

/*
 * NAME:	shift_key()
 * DESCRIPTION:	shift out the lowest bit of all characters in a key string
 */
private string shift_key(string key)
{
    int i, len;

    /*
     * Believe it or not, but the openssl crypto suite has the parity for
     * DES setkey in the <lowest> bit.
     */
    for (i = 0, len = strlen(key); i < len; i++) {
	key[i] >>= 1;
    }

    return key;
}

/*
 * NAME:	set_keys()
 * DESCRIPTION:	create keys as negotiated
 */
private void set_keys()
{
    string str, client_key, server_key;

    str = make_string(K) + H;
    dstate = hash_sha1(str, "A", session_id)[.. 7];
    estate = hash_sha1(str, "B", session_id)[.. 7];
    client_key = hash_sha1(str, "C", session_id);
    client_key += hash_sha1(str, client_key);
    server_key = hash_sha1(str, "D", session_id);
    server_key += hash_sha1(str, server_key);
    client_mac = hash_sha1(str, "E", session_id) +
		 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
		 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    server_mac = hash_sha1(str, "F", session_id) +
		 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" +
		 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    dkey1 = decrypt("DES key", shift_key(client_key[.. 7]));
    dkey2 = encrypt("DES key", shift_key(client_key[8 .. 15]));
    dkey3 = decrypt("DES key", shift_key(client_key[16 .. 23]));
    ekey1 = encrypt("DES key", shift_key(server_key[.. 7]));
    ekey2 = decrypt("DES key", shift_key(server_key[8 .. 15]));
    ekey3 = encrypt("DES key", shift_key(server_key[16 .. 23]));
}

/*
 * NAME:	start_transport()
 * DESCRIPTION:	start up the transport layer
 */
private void start_transport(string version)
{
    DEBUG("client version is " + version);

    transport_state = TRANSPORT_KEXINIT;
    client_version = version;
    server_kexinit = make_mesg(SSH_MSG_KEXINIT) +
		     better_random_string(16) +
		     make_string("diffie-hellman-group1-sha1") +
		     make_string("ssh-dss") +
		     make_string("3des-cbc") +
		     make_string("3des-cbc") +
		     make_string("hmac-sha1") +
		     make_string("hmac-sha1") +
		     make_string("none") +
		     make_string("none") +
		     make_string("") +
		     make_string("") +
		     "\0" +
		     "\0\0\0\0";
    send_packet(server_kexinit);
}

/*
 * NAME:	receive_packet()
 * DESCRIPTION:	receive a packet from connection
 */
private int receive_packet(string str)
{
    int offset;

    if (transport_state == TRANSPORT_SKIP) {
	transport_state = TRANSPORT_KEXDH;
	return MODE_NOCHANGE;
    }

    switch (str[0]) {
    case SSH_MSG_DISCONNECT:
	return MODE_DISCONNECT;

    case SSH_MSG_IGNORE:
	break;

    case SSH_MSG_UNIMPLEMENTED:
    case SSH_MSG_DEBUG:
	if (transport_state == TRANSPORT_TRANSPORT) {
	    break;
	}
	break;

    case SSH_MSG_KEXINIT:
	if (transport_state == TRANSPORT_KEXINIT) {
	    client_kexinit = str;

	    /* generate random y (0 < y < q) */
	    do {
		y = asn_mod("\1" + better_random_string(strlen(q)), q);
	    } while (strlen(y) < strlen(q) - 1);

	    /* f = g ^ y mod p */
	    f = asn_pow("\2", y, p);

	    offset = 17;			/* type + random */
	    offset += 4 + get_int(str, offset);	/* kex */
	    offset += 4 + get_int(str, offset);	/* host key */
	    offset += 4 + get_int(str, offset);	/* decrypt */
	    offset += 4 + get_int(str, offset);	/* encrypt */
	    offset += 4 + get_int(str, offset);	/* demac */
	    offset += 4 + get_int(str, offset);	/* mac */
	    offset += 4 + get_int(str, offset);	/* decompress */
	    offset += 4 + get_int(str, offset);	/* compress */
	    offset += 4 + get_int(str, offset);	/* de-lang */
	    offset += 4 + get_int(str, offset);	/* lang */
	    if (str[offset]) {
		transport_state = TRANSPORT_SKIP;
	    } else {
		transport_state = TRANSPORT_KEXDH;
	    }
	} else if (transport_state == TRANSPORT_TRANSPORT) {
	    server_kexinit = make_mesg(SSH_MSG_KEXINIT) +
			     better_random_string(16) +
			     make_string("diffie-hellman-group1-sha1") +
			     make_string("ssh-dss") +
			     make_string("3des-cbc") +
			     make_string("3des-cbc") +
			     make_string("hmac-sha1") +
			     make_string("hmac-sha1") +
			     make_string("none") +
			     make_string("none") +
			     make_string("") +
			     make_string("") +
			     "\0" +
			     "\0\0\0\0";
	    send_packet(server_kexinit);
	    transport_state = TRANSPORT_KEXINIT;
	}
	break;

    case SSH_MSG_KEXDH_INIT:
	if (transport_state == TRANSPORT_KEXDH) {
	    e = get_string(str, 1);
	    str = SSHD->query_pub_host_key();

	    /* K = e ^ y mod p */
	    K = asn_pow(e, y, p);

	    /* H = shared secret */
	    H = hash_sha1(make_string(client_version),
			  make_string(SSHD->query_version()),
			  make_string(client_kexinit),
			  make_string(server_kexinit),
			  make_string(str),
			  make_string(e),
			  make_string(f),
			  make_string(K));
	    if (!session_id) {
		session_id = H;
	    }

	    str = make_mesg(SSH_MSG_KEXDH_REPLY) +
		  make_string(str) +
		  make_string(f) +
		  make_string(ssh_dss_sign(H, SSHD->query_host_key()));
	    send_packet(str);
	    transport_state = TRANSPORT_NEWKEYS;
	}
	break;

    case SSH_MSG_NEWKEYS:
	if (transport_state == TRANSPORT_NEWKEYS) {
	    send_packet(make_mesg(SSH_MSG_NEWKEYS));
	    set_keys();
	    transport_state = TRANSPORT_TRANSPORT;
	}
	break;

    default:
	if (transport_state == TRANSPORT_TRANSPORT) {
	    return userauth(str);
	}
	break;
    }

    return MODE_NOCHANGE;
}

/*
 * NAME:	create_transport()
 * DESCRIPTION:	initialize transport layer
 */
private void create_transport()
{
    /* p = 2^1024 - 2^960 - 1 + 2^64 * floor( 2^894 Pi + 129093 ) */
    p = "\0" +
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2\x21\x68\xC2\x34" +
	"\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1\x29\x02\x4E\x08\x8A\x67\xCC\x74" +
	"\x02\x0B\xBE\xA6\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD" +
	"\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D\xF2\x5F\x14\x37" +
	"\x4F\xE1\x35\x6D\x6D\x51\xC2\x45\xE4\x85\xB5\x76\x62\x5E\x7E\xC6" +
	"\xF4\x4C\x42\xE9\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED" +
	"\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11\x7C\x4B\x1F\xE6" +
	"\x49\x28\x66\x51\xEC\xE6\x53\x81\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    /* q = (p - 1) / 2 */
    q = asn_rshift(p, 1);
}


/* ========================================================================= *
 *			    Section 3: authentication			     *
 * ========================================================================= */

/*
 * NAME:	userauth_banner()
 * DESCRIPTION:	display a banner during the authentication period
 */
private int userauth_banner(string str)
{
    return send_packet(make_mesg(SSH_MSG_USERAUTH_BANNER) +
		       make_string(str) +
		       make_string("en"));
}

/*
 * NAME:	userauth()
 * DESCRIPTION:	respond to a userauth service request
 */
private int userauth(string str)
{
    string name, service, method, password;
    int offset;

    switch (str[0]) {
    case SSH_MSG_SERVICE_REQUEST:
	if (get_string(str, 1) == "ssh-userauth" && !query_user()) {
	    send_packet(make_mesg(SSH_MSG_SERVICE_ACCEPT) +
			make_string("ssh-userauth"));
	} else {
	    send_packet(make_mesg(SSH_MSG_DISCONNECT) +
			make_int(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE) +
			make_string("service not available") +
			make_string("en"));
	    return MODE_DISCONNECT;
	}
	break;

    case SSH_MSG_USERAUTH_REQUEST:
	if (!query_user()) {
	    name = get_string(str, 1);
	    offset = strlen(name) + 5;
	    service = get_string(str, offset);
	    offset += strlen(service) + 4;
	    method = get_string(str, offset);
	    offset += strlen(method) + 4;

	    if (service == "ssh-connection" && method == "password" &&
		!str[offset]) {
		password = get_string(str, offset + 1);
		if (conn::receive_message(nil, name) != MODE_DISCONNECT &&
		    query_user() &&
		    conn::receive_message(nil, password) != MODE_DISCONNECT) {
		    send_packet(make_mesg(SSH_MSG_USERAUTH_SUCCESS));
		    break;
		}
		DEBUG("login failed for " + name);
		send_packet(make_mesg(SSH_MSG_USERAUTH_FAILURE) +
			    make_string("login failed") +
			    "\0");
	    }
	}
	send_packet(make_mesg(SSH_MSG_USERAUTH_FAILURE) +
		    make_string("password") +
		    "\0");
	break;

    default:
	if (query_user()) {
	    return client(str);
	}
	break;
    }

    return MODE_NOCHANGE;
}


/* ========================================================================= *
 *			  Section 4: connection layer			     *
 * ========================================================================= */

int channel;		/* channel ID */
int window_size;	/* transmit window */
int packet_size;	/* maximum packet size */
int program;		/* program started? */

/*
 * NAME:	message()
 * DESCRIPTION:	send a message to the client
 */
int message(string str)
{
    if (channel >= 0 && window_size >= strlen(str)) {
	window_size -= strlen(str);
	while (strlen(str) > packet_size) {
	    send_packet(make_mesg(SSH_MSG_CHANNEL_DATA) +
			make_int(channel) +
			make_string(str[.. packet_size - 1]));
	    str = str[packet_size ..];
	}
	send_packet(make_mesg(SSH_MSG_CHANNEL_DATA) +
		    make_int(channel) +
		    make_string(str));
	return TRUE;
    }
    return FALSE;
}

/*
 * NAME:	client()
 * DESCRIPTION:	handle a message from the client
 */
private int client(string str)
{
    int offset, channel_id;
    string type;

    switch (str[0]) {
    case SSH_MSG_GLOBAL_REQUEST:
	type = get_string(str, 1);
	offset = strlen(type) + 5;
	if (str[offset]) {
	    send_packet(make_mesg(SSH_MSG_REQUEST_FAILURE));
	}
	break;

    case SSH_MSG_CHANNEL_OPEN:
	type = get_string(str, 1);
	offset = 12;
	channel_id = get_int(str, offset);
	offset += 4;
	if (type != "session") {
	    send_packet(make_mesg(SSH_MSG_CHANNEL_OPEN_FAILURE) +
			make_int(channel_id) +
			make_int(SSH_OPEN_UNKNOWN_CHANNEL_TYPE) +
			make_string("unknown channel type") +
			make_string("en"));
	    break;
	}
	if (channel >= 0) {
	    send_packet(make_mesg(SSH_MSG_CHANNEL_OPEN_FAILURE) +
			make_int(channel_id) +
			make_int(SSH_OPEN_RESOURCE_SHORTAGE) +
			make_string("out of channels") +
			make_string("en"));
	    break;
	}

	channel = channel_id;
	window_size = get_int(str, offset);
	offset += 4;
	packet_size = get_int(str, offset);
	send_packet(make_mesg(SSH_MSG_CHANNEL_OPEN_CONFIRMATION) +
		    make_int(channel_id) +
		    make_int(channel_id) +
		    make_int(0xffffffff) +
		    make_int(2048));
	break;

    case SSH_MSG_CHANNEL_CLOSE:
	if (get_int(str, 1) == channel) {
	    send_packet(make_mesg(SSH_MSG_CHANNEL_CLOSE) +
			make_int(channel));
	    channel = -1;
	    program = FALSE;
	}
	break;

    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
	if (get_int(str, 1) == channel) {
	    window_size += get_int(str, 5);
	}
	break;

    case SSH_MSG_CHANNEL_DATA:
	if (get_int(str, 1) == channel && program) {
	    str = get_string(str, 5);
	    return conn::receive_message(nil, str[.. strlen(str) - 2]);
	}
	break;

    case SSH_MSG_CHANNEL_REQUEST:
	channel_id = get_int(str, 1);
	type = get_string(str, 5);
	offset = strlen(type) + 9;
	if (channel_id == channel && type == "shell" && !program) {
	    program = TRUE;
	    if (str[offset]) {
		send_packet(make_mesg(SSH_MSG_CHANNEL_SUCCESS) +
			    make_int(channel_id));
	    }
	} else if (str[offset]) {
	    send_packet(make_mesg(SSH_MSG_CHANNEL_FAILURE) +
			make_int(channel_id));
	}
	break;

    case SSH_MSG_CHANNEL_EXTENDED_DATA:
    case SSH_MSG_CHANNEL_EOF:
	break;	/* ignore */

    default: 
	send_packet(make_mesg(SSH_MSG_UNIMPLEMENTED) +
		    make_int(recv_seqno - 1));
	break;
    }

    return MODE_NOCHANGE;
}

/*
 * NAME:	create_client()
 * DESCRIPTION:	initialize the client layer
 */
private void create_client()
{
    channel = -1;
}


/* ========================================================================= *
 *			   Section 5: compat layer			     *
 * ========================================================================= */

/*
 * NAME:	login()
 * DESCRIPTION:	accept a SSH connection
 */
int login(string str)
{
    if (previous_program() == LIB_CONN) {
	user::connection(previous_object());
	previous_object()->set_mode(MODE_RAW);
	start_transport(str);
    }
    return MODE_RAW;
}

/*
 * NAME:	logout()
 * DESCRIPTION:	disconnect
 */
void logout(int quit)
{
    if (previous_program() == LIB_CONN) {
	conn::close(nil, quit);
	if (quit) {
	    destruct_object(this_object());
	}
    }
}

/*
 * NAME:	set_mode()
 * DESCRIPTION:	pass on mode changes to the real connection object
 */
void set_mode(int mode)
{
    if (SYSTEM() && mode >= MODE_UNBLOCK) {
	query_conn()->set_mode(mode);
    }
}

/*
 * NAME:	message_done()
 * DESCRIPTION:	ready for another message
 */
int message_done()
{
    if (previous_program() == LIB_CONN) {
	object user;
	int mode;

	user = query_user();
	if (user) {
	    mode = user->message_done();
	    if (mode == MODE_DISCONNECT) {
		return MODE_DISCONNECT;
	    }
	    if (mode >= MODE_UNBLOCK) {
		return mode;
	    }
	}
	return MODE_NOCHANGE;
    }
}

/*
 * NAME:	datagram_challenge()
 * DESCRIPTION:	don't allow a datagram channel to be opened
 */
void datagram_challenge(string str)
{
    error("Datagram channel cannot be opened");
}

/*
 * NAME:	datagram()
 * DESCRIPTION:	don't send a datagram to the client
 */
int datagram(string str)
{
    return 0;
}

/*
 * NAME:	disconnect()
 * DESCRIPTION:	forward a disconnect to the connection
 */
void disconnect()
{
    if (previous_program() == LIB_USER) {
	user::disconnect();
    }
}

/*
 * NAME:	create()
 * DESCRIPTION:	initialize secure shell
 */
static void create(int clone)
{
    if (clone) {
	conn::create("telnet");	/* pretend */
	create_packet();
	create_transport();
	create_client();
    }
}
