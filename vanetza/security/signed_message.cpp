#include <vanetza/security/signed_message.hpp>
#include <memory>


namespace vanetza {
    namespace security{
        SignedMessageV3::SignedMessageV3(){
            // Ieee1609Dot2Content unsecuredContent;
            // unsecuredContent.present = Ieee1609Dot2Content_PR_unsecuredData;
            

            this->signed_message.protocolVersion = 3;
            this->signed_message.content = new Ieee1609Dot2Content();
            Ieee1609Dot2Content * content = this->signed_message.content;
            content->present = Ieee1609Dot2Content_PR_signedData;
            content->choice.signedData = new SignedData();
            SignedData_t * signed_data = content->choice.signedData;
            signed_data->hashId = HashAlgorithm_sha256;
            signed_data->tbsData = new ToBeSignedData();
            ToBeSignedData_t * tbs_data = signed_data->tbsData;
            //psid must be accessible from the outside
            tbs_data->headerInfo.psid = 0;
            this->psid = &(tbs_data->headerInfo.psid);
            //generation delta time be accessible from the outside
            tbs_data->headerInfo.generationTime = new Time64_t();
            this->generation_time = tbs_data->headerInfo.generationTime;

            tbs_data->payload = new SignedDataPayload();
            SignedDataPayload * payload = tbs_data->payload;
            payload->data = new Ieee1609Dot2Data();
            Ieee1609Dot2Data * unsecured_data = payload->data;
            unsecured_data->protocolVersion = 3;
            unsecured_data->content = new Ieee1609Dot2Content();
            Ieee1609Dot2Content * unsecured_content = unsecured_data->content;
            unsecured_content->present = Ieee1609Dot2Content_PR_unsecuredData;
            //Must be accessible from the outside
            //unsecured_content->choice.unsecuredData = new Opaque_t();
            this->payload=&(unsecured_content->choice.unsecuredData);

            this->signature = &(signed_data->signature);
            this->signer = &(signed_data->signer);

        }
    
        SignedMessageV3::~SignedMessageV3(){
            ASN_STRUCT_FREE(asn_DEF_EtsiTs103097Data, &(this->signed_message));
        }

    }

}
