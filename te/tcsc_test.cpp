/*
  Copyright (C) 2018-2019 SKALE Labs
  This file is part of libBLS.
  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.
  You should have received a copy of the GNU Affero General Public License
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.
  @file dkg_key_gen.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <dkg/dkg.h>
#include <ctime>

#include <fstream>

#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKeyShare.h>


#define EXPAND_AS_STR( x ) __EXPAND_AS_STR__( x )
#define __EXPAND_AS_STR__( x ) #x

static bool output1 = false;
static bool output2 = false;
double net_overload = net_overload;

double keyGeneration( const size_t t, const size_t n) {
    libBLS::Dkg dkg_instance = libBLS::Dkg( t, n );

    clock_t s[10], e[10];
    double sum[10];

    std::vector< std::vector< libff::alt_bn128_Fr > > polynomial( n );

    s[1] = clock();
    for ( auto& pol : polynomial ) {
        pol = dkg_instance.GeneratePolynomial();
    }

    std::vector< std::vector< libff::alt_bn128_Fr > > secret_key_contribution( n );
    for ( size_t i = 0; i < n; ++i ) {
        secret_key_contribution[i] = dkg_instance.SecretKeyContribution( polynomial[i] );
    }

    std::vector< std::vector< libff::alt_bn128_G2 > > verification_vector( n );
    for ( size_t i = 0; i < n; ++i ) {
        verification_vector[i] = dkg_instance.VerificationVector( polynomial[i] );
    }

    e[1] = s[2] = clock();

    for ( size_t i = 0; i < n; ++i ) {
        for ( size_t j = i; j < n; ++j ) {
            std::swap( secret_key_contribution[j][i], secret_key_contribution[i][j] );
        }
    }

    e[2] = s[3] = clock();

    for ( size_t i = 0; i < n; ++i ) {
        for ( size_t j = 0; j < n; ++j ) {
            if ( !dkg_instance.Verification(
                     i, secret_key_contribution[i][j], verification_vector[j] ) ) {
                throw std::runtime_error( "not verified" );
            }
        }
    }

    e[3] = s[4] = clock();

    std::vector< std::shared_ptr< BLSPrivateKeyShare > > skeys;
    libff::alt_bn128_G2 common_public_key = libff::alt_bn128_G2::zero();
    for ( size_t i = 0; i < n; ++i ) {
        common_public_key = common_public_key + polynomial[i][0] * libff::alt_bn128_G2::one();
        BLSPrivateKeyShare cur_skey(
            dkg_instance.SecretKeyShareCreate( secret_key_contribution[i] ), t, n );
        skeys.push_back( std::make_shared< BLSPrivateKeyShare >( cur_skey ) );
    }

    e[4] = clock();

    if (output1) {
        for ( int i = 1; i <= 4; ++i ) {
            if ( i == 2 ) {
                sum[i] = double (e[i] - s[i]) + net_overload * n * n;
            } else {
                sum[i] = double (e[i] - s[i]) / n;
            }
            printf( " & %.2lf", sum[i] / 1000);
        }
        puts( " \\\\ \n" );
    }

    double tot = 0;
    for ( int i = 1; i <= 4; ++i ) {
        if ( i == 2 ) {
            tot += double (e[i] - s[i]) + net_overload * n * n;
        } else {
            tot += double (e[i] - s[i]) / n;
        }
    }
    return tot;
}

void test_distribution() {
    size_t n;
    int loops;
    n = 10;
    loops = 1000;
    std::cout << "n,time(ms)" << std::endl;
    clock_t s, e;

    for (n = 5; n <= 20; n += 5) {
        s = clock();
        for (int i = 0; i < loops; ++i) {
            keyGeneration( 1, 1 );
        }
        e = clock();

        std::cout << n << ',' << (double( e - s ) / loops + net_overload * n) / 1000 << std::endl;
    }

    n = 50;
    s = clock();
    for (int i = 0; i < loops; ++i) {
        keyGeneration( 1, 1 );
    }
    e = clock();

    std::cout << n << ',' << (double( e - s ) / loops + net_overload * n) / 1000 << std::endl;

}

void test_isolation() {
    int n;
    int loops;
    loops = 1000;
    std::cout << "n,time(ms)" << std::endl;
    clock_t s, e;

    for (n = 5; n <= 20; n += 5) {
        s = clock();
        for (int i = 0; i < loops; ++i) {
            keyGeneration( 1, 1 );
        }
        e = clock();

        std::cout << n << ',' << (double( e - s ) / loops + net_overload * n) / 1000 << std::endl;
    }

    n = 50;
    s = clock();
    for (int i = 0; i < loops; ++i) {
        keyGeneration( 1, 1 );
    }
    e = clock();

    std::cout << n << ',' << (double( e - s ) / loops + net_overload * n) / 1000 << std::endl;

}

void test_negotiation(bool output) {
    output1 = output;
    int n;
    int loops;
    loops = 1000;
    std::cout << "n,time(ms)" << std::endl;
    double tot;

    for (n = 5; n <= 20; n += 5) {
        tot = 0;
        for (int i = 0; i < loops; ++i) {
            tot += keyGeneration( 1, n );
        }

        std::cout << n << ',' << (tot / loops) / 1000 << std::endl;
    }

    n = 50;
    tot = 0;
    for (int i = 0; i < loops; ++i) {
        tot += keyGeneration( 1, n );
    }

    std::cout << n << ',' << (tot / loops) / 1000 << std::endl;
}

int main( int argc, const char* argv[] ) {
//    test_distribution();
//    test_isolation();
//    test_negotiation(true);
return 0;
}
