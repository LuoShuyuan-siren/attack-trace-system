"""Zeek 日志测试数据生成器。"""

from pathlib import Path


def create_conn_log(filepath: Path) -> None:
    """生成 Zeek conn.log 测试数据。"""
    content = """#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1000000000.000000	CXYZ123	192.168.1.1	12345	10.0.0.1	80	tcp	http	1.000000	100	200	SF
1000000001.000000	CXYZ124	192.168.1.1	54321	8.8.8.8	53	udp	dns	0.000100	60	120	SF
1000000002.000000	CXYZ125	192.168.1.2	23456	10.0.0.2	443	tcp	ssl	3600.000000	5000	100000	SF
"""
    filepath.write_text(content)


def create_dns_log(filepath: Path) -> None:
    """生成 Zeek dns.log 测试数据。"""
    content = """#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qtype_name	rcode_name	answers	TTL
1000000000.000000	DABC111	192.168.1.1	54321	8.8.8.8	53	udp	0x1234	0.000100	example.com	A	NOERROR	93.184.216.34	3600
1000000001.000000	DABC112	192.168.1.1	54322	8.8.8.8	53	udp	0x1235	0.000100	a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.example.com	A	NOERROR	93.184.216.34	3600
1000000002.000000	DABC113	192.168.1.1	54323	8.8.8.8	53	udp	0x1236	0.000100	thisisaverylongsubdomainnamethatexceedsnormallimits.example.com	TXT	NOERROR	-	0
1000000003.000000	DABC114	192.168.1.1	54324	8.8.8.8	53	udp	0x1237	0.000100	nonexistent.example.com	A	NXDOMAIN	-	0
"""
    filepath.write_text(content)


def create_http_log(filepath: Path) -> None:
    """生成 Zeek http.log 测试数据。"""
    content = """#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_content_type
1000000000.000000	HABC111	192.168.1.1	12345	10.0.0.1	80	0	GET	example.com	/	-	HTTP/1.1	Mozilla/5.0	-	0	200	200	text/html
1000000001.000000	HABC112	192.168.1.1	12346	10.0.0.1	80	0	POST	example.com	/api/upload/this-is-a-very-long-uri-with-encoded-data-aGVsbG93b3JsZA	-	HTTP/1.1	curl/7.68.0	-	10485760	0	200	OK	application/json
1000000002.000000	HABC113	192.168.1.1	12347	10.0.0.1	80	0	GET	example.com	/health	-	HTTP/1.1	Python/3.8	-	0	200	OK	text/plain
"""
    filepath.write_text(content)


def create_ssl_log(filepath: Path) -> None:
    """生成 Zeek ssl.log 测试数据。"""
    content = """#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert
1000000002.000000	SABC111	192.168.1.2	23456	10.0.0.2	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	-	www.example.com	F	-
"""
    filepath.write_text(content)


def create_all_zeek_logs(directory: Path) -> None:
    """生成所有 Zeek 测试日志。"""
    directory.mkdir(parents=True, exist_ok=True)
    create_conn_log(directory / "conn.log")
    create_dns_log(directory / "dns.log")
    create_http_log(directory / "http.log")
    create_ssl_log(directory / "ssl.log")
