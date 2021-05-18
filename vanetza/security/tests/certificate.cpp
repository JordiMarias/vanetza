#include <gtest/gtest.h>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/tests/check_certificate.hpp>
#include <vanetza/security/tests/serialization.hpp>

using namespace vanetza::security;

vanetza::ByteBuffer from_hexstring(std::string hex_string)
{
    size_t len = hex_string.length();
    vanetza::ByteBuffer out;
    for (size_t i = 0; i < len; i += 2)
    {
        std::istringstream strm(hex_string.substr(i, 2));
        uint8_t x;
        strm >> std::hex >> x;
        out.push_back(x);
    }
    return out;
}

TEST(Certificate, WebValidator_RootCA_v2)
{
    const char str[] =
        "0200040C547275737465645F526F6F74808D000004F1817DD05116B855A853F80DB171A3A470D431"
        "70EA7EEFD8EF392D66ECEFBE501CEBA19963C9B6447574424FFF1BB89485743F4D09A72B715FC73C"
        "87E5F70A110101000441279A383B80C812B72B1A5F5C3C590E5041C634A1ADCC4CE58393CA046D3C"
        "619717AEF634F7D80D5F6A29FA7F86EBF823ACE0097A71EE0DF0793034B0D3797C02E0200224250B"
        "0114B12B03154E0D83030000007D12BADF99D7070BCB237ED1FA7A5D86FD47E6ABA8E616B35E95A2"
        "856FC6E26A493E1215BCEE8BEA18B8ED52FB240716C4D4EC7D7C0167F0F032CBB87DF611D9";

    Certificate c;
    deserialize_from_hexstring(str, c);
    check(c, serialize_roundtrip(c));
}

TEST(Certificate, WebValidator_AuthorizationAuthority1_v2)
{
    const char str[] =
        "0201F5425279310C0379020A547275737465645F4141808D00000432B9C37AC51D25863A7872EF40"
        "5DB43DF37FA73411B2C0539FD39DF38828F86C946CB09039C0A9694A650D9104BA62C5A7588AEF8F"
        "68935F0D170373968131CD01010004E6C956FBEDCC969935BE832E4DE599CBFD687D81495C58B3C1"
        "2028F92489D4AF76B64D340BE2ACE8D7E2A789FE09A5F3B84F5E65BF54A07FAF74696131E762E302"
        "E0200224250B0114B12B03154E0D8303000000CC6255F38BC8844FAC2A31DE3420E65F23DBC97DC8"
        "66C840516328F27850B3520FC2A812A49DD989BFB0ECE408E53B375006974D1DA4EFD6FC5465B3F8"
        "946183";
    Certificate c;
    deserialize_from_hexstring(str, c);
    check(c, serialize_roundtrip(c));
}

TEST(Certificate, WebValidator_AuthorizationAuthority2_v2)
{
    const char str[] =
        "0201F5425279310C0379020A547275737465645F4141808D00000401418E994657434A71E034E530"
        "B1E77A8AFAC37561132C83D45C442499228CA78573F14BE034A4958108A654CAC60F15BB35907E33"
        "D0E97F8D7EAF64A1F43547010100047C5C8D8B86CF8A00A53F3CD23FCCF13D078555CC8EF27DC439"
        "780EB8EF376237FF668055DA476CC82956F6FEBFA051A6D927E70D826DB0338E42819F026AEBAA02"
        "E0200224250B0114B12B03154E0D83030000005145571104D52DD7094C577719C7CA430D59608D5F"
        "EFD10DB3E61B7C5FD3E4716224F96ED5AB4EB7F860C15347B66E23EA12E0A186A1A80B96C6E5DE05"
        "416A87";
    Certificate c;
    deserialize_from_hexstring(str, c);
    check(c, serialize_roundtrip(c));
}

TEST(Certificate, WebValidator_AuthorizationTicket1_v2)
{
    const char str[] =
        "02015388DEC640C6E19E010052000004B27D4D442F58E065F8D500478929BC843940F3C34D46C547"
        "5803C03594E35BD7E0132FD01634E86D4F50F7F2366988E12525232D00D03E98FC21CA8E5D0AF370"
        "02E0210B24030100002504010000000B0114E9DB83154CBC0203000000553C8D2B8A4E53F3D84A88"
        "37BEEBE83D5C7F68484AC5EFCEEFCC7B0BC5E9531754AAF58BF90790A10F2FD11796A85E13DFFAAC"
        "6073D2068465DA733994CD0C71";
    Certificate c;
    deserialize_from_hexstring(str, c);
    check(c, serialize_roundtrip(c));
}

TEST(Certificate, CertificateV3_constructor_and_serializer)
{
    //std::string xer_certificate = "<EtsiTs103097Certificate><version>3</version><type><explicit/></type><issuer><self><sha256/></self></issuer><toBeSigned><id><name>rootca.test.com</name></id><cracaId>000000</cracaId><crlSeries>0</crlSeries><validityPeriod><start>470833944</start><duration><years>35</years></duration></validityPeriod><appPermissions><PsidSsp><psid>622</psid><ssp><opaque>01</opaque></ssp></PsidSsp><PsidSsp><psid>624</psid><ssp><opaque>0138</opaque></ssp></PsidSsp></appPermissions><certIssuePermissions><PsidGroupPermissions><subjectPermissions><all/></subjectPermissions><minChainLength>3</minChainLength><chainLengthRange>-1</chainLengthRange><eeType>11</eeType></PsidGroupPermissions></certIssuePermissions><encryptionKey><supportedSymmAlg><aes128Ccm/></supportedSymmAlg><publicKey><eciesNistP256><compressed-y-0>6c8231eb1842c4c4f17db00152e0276b693d49c5e062ddfeb3d46ac5fc9e4994</compressed-y-0></eciesNistP256></publicKey></encryptionKey><verifyKeyIndicator><verificationKey><ecdsaNistP256><compressed-y-0>6c8231eb1842c4c4f17db00152e0276b693d49c5e062ddfeb3d46ac5fc9e4994</compressed-y-0></ecdsaNistP256></verificationKey></verifyKeyIndicator></toBeSigned><signature><ecdsaNistP256Signature><rSig><x-only>65177d3779ad57285e144aa85a39b28bb5c7177e99d63d253b487c9d2202f3a8</x-only></rSig><sSig>7693322b5dd9e348631802188b8d5334df89b32351d5ebd1d2c70703123f8635</sSig></ecdsaNistP256Signature></signature></EtsiTs103097Certificate>";
    std::string hex_string = "0380810019000f816f72746f6163742e73652e746f63006d00000000101c185b0086012380020202806e01010280700202803801010181e00301ff0100c08280826ceb314218c4c47df101b0e0526b273d69c54962e0feddd4b3c56a9efc944980806c82318218ebc442f1c4b07d520127e0696b493de0c5dd62b3fe6ad4fcc5499e809465807d17793757ad5e284a145aa8b239b58b17c7997e3dd63b257c48229df30276a832935d2be3d9634802188b18538ddf34b3895123ebd5d2d107c71203863f0035";
    vanetza::ByteBuffer given = from_hexstring(
        hex_string);
    CertificateV3 certificate(given);
    // vanetza::ByteBuffer when = certificate.serialize();
    
    // ASSERT_EQ(when, given);
}

TEST(Certificate, CertificateV3_get_start_and_end_validity){
    std::string hex_string = "0380810019000f816f72746f6163742e73652e746f63006d00000000101c185b0086012380020202806e01010280700202803801010181e00301ff0100c08280826ceb314218c4c47df101b0e0526b273d69c54962e0feddd4b3c56a9efc944980806c82318218ebc442f1c4b07d520127e0696b493de0c5dd62b3fe6ad4fcc5499e809465807d17793757ad5e284a145aa8b239b58b17c7997e3dd63b257c48229df30276a832935d2be3d9634802188b18538ddf34b3895123ebd5d2d107c71203863f0035";
    vanetza::ByteBuffer given = from_hexstring(
        hex_string);
    CertificateV3 certificate(given);

    vanetza::security::StartAndEndValidity when = certificate.get_start_and_end_validity();

    ASSERT_EQ(when.start_validity, 470833944);
    ASSERT_EQ(when.end_validity, 1574593944);
}

TEST(Certificate, CertificateV3_get_geographic_region){
    std::string hex_string = "0380810019000f816f72746f6163742e73652e746f63006d00000000101c185b0086012380020202806e01010280700202803801010181e00301ff0100c08280826ceb314218c4c47df101b0e0526b273d69c54962e0feddd4b3c56a9efc944980806c82318218ebc442f1c4b07d520127e0696b493de0c5dd62b3fe6ad4fcc5499e809465807d17793757ad5e284a145aa8b239b58b17c7997e3dd63b257c48229df30276a832935d2be3d9634802188b18538ddf34b3895123ebd5d2d107c71203863f0035";
    vanetza::ByteBuffer given = from_hexstring(
        hex_string);
    CertificateV3 certificate(given);
    //TODO
}

