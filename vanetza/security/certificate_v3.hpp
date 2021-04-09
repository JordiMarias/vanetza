#ifndef CERTIFICATE_V3_HPP
#define CERTIFICATE_V3_HPP

#include <vanetza/common/its_aid.hpp>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/validity_restriction.hpp>


namespace vanetza{
    namespace security {
        class CertificateV3{
            public:
                CertificateV3();
                ~CertificateV3();

                uint8_t version() const { return 3; }

                /**
                 * Get subject attribute of a certain type (if present)
                 * \param type of subject attribute
                 */
                const SubjectAttribute* get_attribute(SubjectAttributeType type) const;

                /**
                 * Get validity restriction of a certain type (if present)
                 * \param type of validity restriction
                 */
                const ValidityRestriction* get_restriction(ValidityRestrictionType type) const;

                /**
                 * Remove subject attribute of a certain type (if present)
                 * \param type of subject attribute
                 */
                void remove_attribute(SubjectAttributeType type);

                /**
                 * Remove validity restriction of a certain type (if present)
                 * \param type of validity restriction
                 */
                void remove_restriction(ValidityRestrictionType type);

                /**
                 * Add ITS-AID to certificate's subject attributes
                 * \param aid ITS-AID
                 */
                void add_permission(ItsAid aid);

                /**
                 * Add ITS-AID along with SSP to certificate's subject attributes
                 * \param aid ITS-AID
                 * \param ssp Service Specific Permissions
                 */
                void add_permission(ItsAid aid, const ByteBuffer& ssp);

                /**
                 * Get subject attribute by type
                 * \tparam T subject attribute type
                 * \return subject attribute, nullptr if not found
                 */
                template<SubjectAttributeType T>
                const subject_attribute_type<T>* get_attribute() const
                {
                    using type = subject_attribute_type<T>;
                    const SubjectAttribute* field = get_attribute(T);
                    return boost::get<type>(field);
                }

                /**
                 * Get validity restriction by type
                 * \tparam T validity restriction type
                 * \return validity restriction, nullptr if not found
                 */
                template<ValidityRestrictionType T>
                const validity_restriction_type<T>* get_restriction() const
                {
                    using type = validity_restriction_type<T>;
                    const ValidityRestriction* field = get_restriction(T);
                    return boost::get<type>(field);
                }

            private:
                EtsiTs103097Certificate_t certificate;

        };

    }
}

#endif