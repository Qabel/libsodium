SODIUM_OBJECTS = libsodium/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.o \
		 libsodium/crypto_secretbox/crypto_secretbox.o \
		 libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.o \
		 libsodium/crypto_secretbox/crypto_secretbox_easy.o \
		 libsodium/crypto_stream/salsa208/stream_salsa208.o \
		 libsodium/crypto_stream/salsa208/ref/stream_salsa208_ref.o \
		 libsodium/crypto_stream/xsalsa20/stream_xsalsa20.o \
		 libsodium/crypto_stream/crypto_stream.o \
		 libsodium/crypto_stream/chacha20/stream_chacha20.o \
		 libsodium/crypto_stream/chacha20/ref/chacha20_ref.o \
		 libsodium/crypto_stream/xchacha20/stream_xchacha20.o \
		 libsodium/crypto_stream/salsa2012/stream_salsa2012.o \
		 libsodium/crypto_stream/salsa2012/ref/stream_salsa2012_ref.o \
		 libsodium/crypto_stream/salsa20/stream_salsa20.o \
		 libsodium/crypto_stream/salsa20/ref/salsa20_ref.o \
		 libsodium/randombytes/randombytes.o \
		 libsodium/crypto_core/salsa/ref/core_salsa_ref.o \
		 libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.o \
		 libsodium/crypto_core/hsalsa20/core_hsalsa20.o \
		 libsodium/crypto_core/ed25519/core_ed25519.o \
		 libsodium/crypto_core/ed25519/ref10/ed25519_ref10.o \
		 libsodium/crypto_core/hchacha20/core_hchacha20.o \
		 libsodium/crypto_kdf/crypto_kdf.o \
		 libsodium/crypto_kdf/blake2b/kdf_blake2b.o \
		 libsodium/crypto_auth/hmacsha512/auth_hmacsha512.o \
		 libsodium/crypto_auth/hmacsha256/auth_hmacsha256.o \
		 libsodium/crypto_auth/crypto_auth.o \
		 libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256.o \
		 libsodium/crypto_verify/sodium/verify.o \
		 libsodium/crypto_kx/crypto_kx.o \
		 libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.o \
		 libsodium/crypto_generichash/crypto_generichash.o \
		 libsodium/crypto_generichash/blake2b/generichash_blake2.o \
		 libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.o \
		 libsodium/crypto_generichash/blake2b/ref/blake2b-ref.o \
		 libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.o \
		 libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.o \
		 libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.o \
		 libsodium/sodium/core.o \
		 libsodium/sodium/utils.o \
		 libsodium/sodium/codecs.o \
		 libsodium/sodium/version.o \
		 libsodium/sodium/runtime.o \
		 libsodium/crypto_hash/sha512/cp/hash_sha512_cp.o \
		 libsodium/crypto_hash/sha512/hash_sha512.o \
		 libsodium/crypto_hash/crypto_hash.o \
		 libsodium/crypto_hash/sha256/cp/hash_sha256_cp.o \
		 libsodium/crypto_hash/sha256/hash_sha256.o \
		 libsodium/crypto_scalarmult/crypto_scalarmult.o \
		 libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.o \
		 libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.o \
		 libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.o \
		 libsodium/crypto_onetimeauth/crypto_onetimeauth.o \
		 libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.o \
		 libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.o \
		 libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.o \
		 libsodium/crypto_box/crypto_box_easy.o \
		 libsodium/crypto_box/crypto_box_seal.o \
		 libsodium/crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.o \
		 libsodium/crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.o \
		 libsodium/crypto_box/crypto_box.o \
		 libsodium/crypto_shorthash/crypto_shorthash.o \
		 libsodium/crypto_shorthash/siphash24/shorthash_siphashx24.o \
		 libsodium/crypto_shorthash/siphash24/shorthash_siphash24.o \
		 libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.o \
		 libsodium/crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.o \
		 libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.o \
		 libsodium/crypto_pwhash/argon2/pwhash_argon2i.o \
		 libsodium/crypto_pwhash/argon2/argon2-core.o \
		 libsodium/crypto_pwhash/argon2/argon2-encoding.o \
		 libsodium/crypto_pwhash/argon2/argon2.o \
		 libsodium/crypto_pwhash/argon2/pwhash_argon2id.o \
		 libsodium/crypto_pwhash/argon2/blake2b-long.o \
		 libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.o \
		 libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.o \
		 libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.o \
		 libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.o \
		 libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.o \
		 libsodium/crypto_pwhash/crypto_pwhash.o \
		 libsodium/crypto_sign/crypto_sign.o \
		 libsodium/crypto_sign/ed25519/sign_ed25519.o \
		 libsodium/crypto_sign/ed25519/ref10/keypair.o \
		 libsodium/crypto_sign/ed25519/ref10/obsolete.o \
		 libsodium/crypto_sign/ed25519/ref10/open.o \
		 libsodium/crypto_sign/ed25519/ref10/sign.o

SOURCES += \
	   $(LIBSODIUM_DIR)/src/

CINCLUDES += \
	     -I$(LIBSODIUM_DIR)/src/libsodium/include/ \
	     -I$(LIBSODIUM_DIR)/src/libsodium/include/sodium/

