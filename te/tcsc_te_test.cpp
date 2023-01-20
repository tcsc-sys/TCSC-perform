
#include <dkg/dkg.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>

#include <dkg/DKGTEWrapper.h>
#include <stdio.h>
#include <stdlib.h>
#include <random>

double enc_t[110], dec_t[110];

std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );

std::string spoilMessage( std::string& message ) {
    std::string mes = message;
    size_t ind = rand_gen() % message.length();
    char ch = rand_gen() % 128;
    while ( mes[ind] == ch )
        ch = rand_gen() % 128;
    mes[ind] = ch;
    return mes;
}

void test_te(int loops, int n) {
    clock_t s1, s2, e1, e2;
    size_t num_all = n;
    size_t num_signed = 1;
    std::vector< std::vector< libff::alt_bn128_Fr > > secret_shares_all;
    std::vector< std::vector< libff::alt_bn128_G2 > > public_shares_all;
    std::vector< DKGTEWrapper > dkgs;
    std::vector< TEPrivateKeyShare > skeys;
    std::vector< TEPublicKeyShare > pkeys;

    for ( size_t i = 0; i < num_all; i++ ) {
        DKGTEWrapper dkg_wrap( num_signed, num_all );

        libBLS::Dkg dkg_te( num_signed, num_all );
        std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();
        auto shared_poly = std::make_shared< std::vector< libff::alt_bn128_Fr > >( poly );
        dkg_wrap.setDKGSecret( shared_poly );

        dkgs.push_back( dkg_wrap );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr =
            dkg_wrap.createDKGSecretShares();
        std::shared_ptr< std::vector< libff::alt_bn128_G2 > > public_shares_ptr =
            dkg_wrap.createDKGPublicShares();
        secret_shares_all.push_back( *secret_shares_ptr );
        public_shares_all.push_back( *public_shares_ptr );
    }

    for ( size_t i = 0; i < num_all; i++ )
        for ( size_t j = 0; j < num_all; j++ ) {
            dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                                         std::make_shared< std::vector< libff::alt_bn128_G2 > >(
                                             public_shares_all.at( i ) ) );
        }

    std::vector< std::vector< libff::alt_bn128_Fr > > secret_key_shares;

    for ( size_t i = 0; i < num_all; i++ ) {
        std::vector< libff::alt_bn128_Fr > secret_key_contribution;
        for ( size_t j = 0; j < num_all; j++ ) {
            secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
        }
        secret_key_shares.push_back( secret_key_contribution );
    }

    for ( size_t i = 0; i < num_all; i++ ) {
        TEPrivateKeyShare pkey_share = dkgs.at( i ).CreateTEPrivateKeyShare(
            i + 1, std::make_shared< std::vector< libff::alt_bn128_Fr > >(
                secret_key_shares.at( i ) ) );
        skeys.push_back( pkey_share );
        pkeys.push_back( TEPublicKeyShare( pkey_share, num_signed, num_all ) );
    }

    TEPublicKey common_public = DKGTEWrapper::CreateTEPublicKey(
        std::make_shared< std::vector< std::vector< libff::alt_bn128_G2 > > >(
            public_shares_all ),
        num_signed, num_all );

    std::string message;
    size_t msg_length = 64;
    for ( size_t length = 0; length < msg_length; ++length ) {
        message += char( rand_gen() % 128 );
    }

    auto msg_ptr = std::make_shared< std::string >( message );
    s1 = clock();
    libBLS::Ciphertext cypher = common_public.encrypt( msg_ptr );

    e1 = clock();
    for ( size_t i = 0; i < num_all - num_signed; ++i ) {
        size_t ind4del = rand_gen() % secret_shares_all.size();
        auto pos4del = secret_shares_all.begin();
        advance( pos4del, ind4del );
        secret_shares_all.erase( pos4del );
        auto pos2 = public_shares_all.begin();
        advance( pos2, ind4del );
        public_shares_all.erase( pos2 );
    }

    TEDecryptSet decr_set( num_signed, num_all );
    for ( size_t i = 0; i < num_signed; i++ ) {
        s2 = clock();
        libff::alt_bn128_G2 decrypt = skeys[i].getDecryptionShare( cypher );
        e2 = clock();
        pkeys[i].Verify( cypher, decrypt );
        auto decr_ptr = std::make_shared< libff::alt_bn128_G2 >( decrypt );
        decr_set.addDecrypt( skeys[i].getSignerIndex(), decr_ptr );
    }

    std::string message_decrypted = decr_set.merge( cypher );

    enc_t[loops] = e1 - s1;
    dec_t[loops] = e2 - s2;
}


int main( int argc, const char* argv[] ) {
    int loops = 1000;
    for ( int j = 0; j < loops; ++j ) {
        test_te(j, 1);
    }

    double enc_sum, dec_sum;
    enc_sum = dec_sum = 0;

    std::cout << "bls_enc(us),bls_dec(us)" << std::endl;
    for ( int i = 0; i < loops; ++i ) {
        enc_sum += enc_t[i];
        dec_sum += dec_t[i];
        std::cout << enc_t[i] << ',' << dec_t[i]<< std::endl;
    }

    std::cout << "avg: " << enc_sum / loops << ',' << dec_sum / loops<< std::endl;
}
