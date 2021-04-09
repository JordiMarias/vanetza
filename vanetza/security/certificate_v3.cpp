#include <iostream>
#include <vanetza/security/certificate_v3.hpp>


namespace vanetza{
    namespace security{
        CertificateV3::CertificateV3() {
            this->certificate.version = 3;
            this->certificate.type = CertificateType_explicit;
            this->certificate.issuer.present = IssuerIdentifier_PR_self;
            this->certificate.issuer.choice.self = HashAlgorithm_sha256;
            this->certificate.toBeSigned.id.present = CertificateId_PR_name;
            std::string choice_name = "rootca.test.com";
            OCTET_STRING_fromBuf(&(this->certificate.toBeSigned.id.choice.name), choice_name.c_str(), choice_name.size());
            std::string craca_id = "000000";
            OCTET_STRING_fromBuf(&(this->certificate.toBeSigned.cracaId), craca_id.c_str(), craca_id.size());
            this->certificate.toBeSigned.crlSeries = 0;
            this->certificate.toBeSigned.validityPeriod.start = 470833944;
            this->certificate.toBeSigned.validityPeriod.duration.present = Duration_PR_years;
            this->certificate.toBeSigned.validityPeriod.duration.choice.years = 35;
            this->certificate.toBeSigned.appPermissions;
            //asn_sequence_add(this->certificate.toBeSigned.appPermissions->list, new );

        }
    }
}