#ifndef SIGNED_MESSAGE_HPP
#define SIGNED_MESSAGE_HPP

#include <vanetza/asn1/security/EtsiTs103097Data.h>



namespace vanetza {
    namespace security{
        /**
         * \brief Signed Message as described in ETSI TS 103 097 - V1.3.1
         *
         * This class makes easier create/interact with signed messages as described in ETSI TS 103 097 - V1.3.1
         * 
         */
        class SignedMessageV3{
            public:
                SignedMessageV3();
                SignedMessageV3(SignedMessageV3& signed_message);
                ~SignedMessageV3();
                
            private:
                EtsiTs103097Data_t signed_message;
                Time64_t* generation_time;
                Opaque_t* payload;
                Psid_t* psid;
                Signature_t* signature;
                SignerIdentifier_t* signer;
                
        };

    }
}


#endif /* SIGNED_MESSAGE_HPP */
