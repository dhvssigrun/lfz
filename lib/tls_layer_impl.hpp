#ifndef LIBFILEZILLA_TLS_LAYER_IMPL_HEADER
#define LIBFILEZILLA_TLS_LAYER_IMPL_HEADER

#if defined(_MSC_VER)
typedef std::make_signed_t<size_t> ssize_t;
#endif

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "libfilezilla/buffer.hpp"
#include "libfilezilla/logger.hpp"
#include "libfilezilla/socket.hpp"
#include "libfilezilla/tls_info.hpp"
#include "libfilezilla/tls_layer.hpp"

#include <optional>

namespace fz {
class tls_system_trust_store;
class logger_interface;

struct cert_list_holder final
{
	cert_list_holder() = default;
	~cert_list_holder() {
		for (unsigned int i = 0; i < certs_size; ++i) {
			gnutls_x509_crt_deinit(certs[i]);
		}
		gnutls_free(certs);
	}

	cert_list_holder(cert_list_holder const&) = delete;
	cert_list_holder& operator=(cert_list_holder const&) = delete;

	gnutls_x509_crt_t * certs{};
	unsigned int certs_size{};
};

class tls_layer;
class tls_layer_impl final
{
public:
	tls_layer_impl(tls_layer& layer, tls_system_trust_store * systemTrustStore, logger_interface & logger);
	~tls_layer_impl();

	bool client_handshake(std::vector<uint8_t> const& session_to_resume, native_string const& session_hostname, std::vector<uint8_t> const& required_certificate, event_handler * verification_handler);

	bool server_handshake(std::vector<uint8_t> const& session_to_resume, std::string_view const& preamble, tls_server_flags flags);

	int connect(native_string const& host, unsigned int port, address_type family);

	int read(void *buffer, unsigned int size, int& error);
	int write(void const* buffer, unsigned int size, int& error);

	int shutdown();

	void set_verification_result(bool trusted);

	socket_state get_state() const {
		return state_;
	}

	std::vector<uint8_t> get_session_parameters() const;
	std::vector<uint8_t> get_raw_certificate() const;

	std::string get_protocol() const;
	std::string get_key_exchange() const;
	std::string get_cipher() const;
	std::string get_mac() const;
	int get_algorithm_warnings() const;

	bool resumed_session() const;

	static std::string list_tls_ciphers(std::string const& priority);

	bool set_certificate_file(native_string const& keyfile, native_string const& certsfile, native_string const& password, bool pem);

	bool set_certificate(std::string_view const& key, std::string_view const& certs, native_string const& password, bool pem);

	static std::string get_gnutls_version();

	ssize_t push_function(void const* data, size_t len);
	ssize_t pull_function(void* data, size_t len);

	static std::pair<std::string, std::string> generate_selfsigned_certificate(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames);
	static std::pair<std::string, std::string> generate_csr(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem);

	int shutdown_read();

	void set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block);

	std::string get_alpn() const;
	native_string get_hostname() const;

	static int load_certificates(std::string_view const& in, bool pem, gnutls_x509_crt_t *& certs, unsigned int & certs_size, bool & sort);
	static bool extract_cert(gnutls_x509_crt_t const& cert, x509_certificate& out, bool last, logger_interface * logger);

	void set_min_tls_ver(tls_ver ver);
	void set_max_tls_ver(tls_ver ver);

	void set_unexpected_eof_cb(std::function<bool()> && cb);

private:
	bool init();
	void deinit();

	bool init_session(bool client, int extra_flags = 0);
	void deinit_session();

	int continue_write();
	int continue_handshake();
	int continue_shutdown();

	int verify_certificate();
	bool certificate_is_blacklisted(cert_list_holder const& certificates);
	bool certificate_is_blacklisted(gnutls_x509_crt_t const& cert);

	void log_error(int code, std::wstring const& function, logmsg::type logLevel = logmsg::error);
	void log_alert(logmsg::type logLevel);

	// Failure logs the error, uninits the session and sends a close event
	void failure(int code, bool send_close, std::wstring const& function = std::wstring());

	int do_call_gnutls_record_recv(void* data, size_t len);

	void operator()(event_base const& ev);
	void on_socket_event(socket_event_source* source, socket_event_flag t, int error);
	void forward_hostaddress_event(socket_event_source* source, std::string const& address);

	void on_read();
	void on_send();

	bool get_sorted_peer_certificates(gnutls_x509_crt_t *& certs, unsigned int & certs_size);

	static std::vector<x509_certificate::subject_name> get_cert_subject_alt_names(gnutls_x509_crt_t cert);

	void log_verification_error(int status);

	void set_hostname(native_string const& host);

	bool do_set_alpn();

	int new_session_ticket();

	tls_layer& tls_layer_;

	logger_interface & logger_;

	std::function<bool()> unexpected_eof_cb_;

	gnutls_session_t session_{};

	std::vector<uint8_t> ticket_key_;
	std::vector<uint8_t> session_db_key_;
	std::vector<uint8_t> session_db_data_;

	gnutls_certificate_credentials_t cert_credentials_{};

	std::vector<std::string> alpn_;
	bool alpn_server_priority_{};

	socket_state state_{};

	bool handshake_successful_{};
	bool sent_closure_alert_{};

	bool can_read_from_socket_{false};
	bool can_write_to_socket_{false};

	bool shutdown_silence_read_errors_{true};

	// gnutls_record_send has strange semantics, it needs to be called again
	// with either 0 data and 0 length after GNUTLS_E_AGAIN, to actually send
	// previously queued data. We unfortunately do not know how much data has
	// been queued and thus need to make a copy of the input up to
	// gnutls_record_get_max_size()
	buffer send_buffer_;

	// Sent out just before the handshake itself
	buffer preamble_;

	std::vector<uint8_t> required_certificate_;

	friend class tls_layer;
	friend class tls_layerCallbacks;

	native_string hostname_;

	tls_system_trust_store* system_trust_store_{};

	event_handler * verification_handler_{};

	tls_ver min_tls_ver_{tls_ver::v1_0};
	std::optional<tls_ver> max_tls_ver_;

	int socket_error_{}; // Set in the push and pull functions if reading/writing fails fatally
	bool socket_eof_{};

	bool initialized_{};
	bool server_{};

	bool write_blocked_by_send_buffer_{};

	bool send_new_ticket_{};

#if DEBUG_SOCKETEVENTS
	bool debug_can_read_{};
	bool debug_can_write_{};
#endif
};

std::string read_certificates_file(native_string const& certsfile, logger_interface * logger);

}

#endif
