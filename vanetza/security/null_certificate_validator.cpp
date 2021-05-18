#include <vanetza/security/null_certificate_validator.hpp>

namespace vanetza
{
namespace security
{

NullCertificateValidator::NullCertificateValidator() : m_check_result(CertificateInvalidReason::Unknown_Signer)
{
}

CertificateValidity NullCertificateValidator::check_certificate(const CertificateVariant&)
{
    return m_check_result;
}

void NullCertificateValidator::certificate_check_result(const CertificateValidity& result)
{
    m_check_result = result;
}

} // namespace security
} // namespace vanetza
