#include "libfilezilla/tls_info.hpp"
#include "tls_layer_impl.hpp"

namespace fz {
x509_certificate::x509_certificate(
		std::vector<uint8_t> const& rawData,
		datetime const& activation_time, datetime const& expiration_time,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<subject_name> const& alt_subject_names,
		bool const self_signed)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(alt_subject_names)
	, self_signed_(self_signed)
{
}

x509_certificate::x509_certificate(
	std::vector<uint8_t> && rawData,
	datetime const& activation_time, datetime const& expiration_time,
	std::string const& serial,
	std::string const& pkalgoname, unsigned int bits,
	std::string const& signalgoname,
	std::string const& fingerprint_sha256,
	std::string const& fingerprint_sha1,
	std::string const& issuer,
	std::string const& subject,
	std::vector<subject_name> && alt_subject_names,
	bool const self_signed)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(alt_subject_names)
	, self_signed_(self_signed)
{
}

tls_session_info::tls_session_info(std::string const& host, unsigned int port,
		std::string const& protocol,
		std::string const& key_exchange,
		std::string const& session_cipher,
		std::string const& session_mac,
		int algorithm_warnings,
		std::vector<x509_certificate> && peer_certificates,
		std::vector<x509_certificate> && system_trust_chain,
		bool hostname_mismatch)
	: host_(host)
	, port_(port)
	, protocol_(protocol)
	, key_exchange_(key_exchange)
	, session_cipher_(session_cipher)
	, session_mac_(session_mac)
	, algorithm_warnings_(algorithm_warnings)
	, peer_certificates_(peer_certificates)
	, system_trust_chain_(system_trust_chain)
	, hostname_mismatch_(hostname_mismatch)
{
}

std::vector<x509_certificate> load_certificates_file(native_string const& certsfile, bool pem, bool sort, logger_interface * logger)
{
	std::string certdata = read_certificates_file(certsfile, logger);
	if (certdata.empty()) {
		return {};
	}

	return load_certificates(certdata, pem, sort, logger);
}

std::vector<x509_certificate> load_certificates(std::string_view const& certdata, bool pem, bool sort, logger_interface * logger)
{
	cert_list_holder certs;
	if (tls_layer_impl::load_certificates(certdata, pem, certs.certs, certs.certs_size, sort) != GNUTLS_E_SUCCESS) {
		return {};
	}

	std::vector<x509_certificate> certificates;
	certificates.reserve(certs.certs_size);
	for (unsigned int i = 0; i < certs.certs_size; ++i) {
		x509_certificate cert;
		if (tls_layer_impl::extract_cert(certs.certs[i], cert, i + 1 == certs.certs_size, logger)) {
			certificates.emplace_back(std::move(cert));
		}
		else {
			certificates.clear();
			break;
		}
	}

	return certificates;
}

}
