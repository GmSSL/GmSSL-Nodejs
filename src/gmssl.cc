/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <napi.h>
#include <cstring>
#include <vector>

#include <gmssl/version.h>
#include <gmssl/rand.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm9.h>
#include <gmssl/zuc.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/mem.h>

// Undef macros that conflict with our C++ constants
#undef SM3_DIGEST_SIZE
#undef SM3_HMAC_SIZE
#undef SM3_PBKDF2_MIN_ITER
#undef SM3_PBKDF2_MAX_ITER
#undef SM3_PBKDF2_MAX_SALT_SIZE
#undef SM3_PBKDF2_DEFAULT_SALT_SIZE
#undef SM3_PBKDF2_MAX_KEY_SIZE
#undef SM4_KEY_SIZE
#undef SM4_BLOCK_SIZE
#undef SM4_GCM_MAX_IV_SIZE
#undef SM4_GCM_MIN_IV_SIZE
#undef SM4_GCM_DEFAULT_IV_SIZE
#undef SM4_GCM_DEFAULT_TAG_SIZE
#undef SM4_GCM_MAX_TAG_SIZE
#undef SM2_DEFAULT_ID
#undef SM2_MAX_SIGNATURE_SIZE
#undef SM2_MIN_PLAINTEXT_SIZE
#undef SM2_MAX_PLAINTEXT_SIZE
#undef SM2_MIN_CIPHERTEXT_SIZE
#undef SM2_MAX_CIPHERTEXT_SIZE
#undef SM9_MAX_ID_SIZE
#undef SM9_MAX_PLAINTEXT_SIZE
#undef SM9_MAX_CIPHERTEXT_SIZE
#undef SM9_SIGNATURE_SIZE
#undef ZUC_KEY_SIZE
#undef ZUC_IV_SIZE

// ============================================================
// Constants
// ============================================================

static const char* const GMSSL_NODEJS_VERSION = "GmSSL Node.js 1.0.0";

constexpr int SM3_DIGEST_SIZE = 32;
constexpr int SM3_HMAC_MIN_KEY_SIZE = 16;
constexpr int SM3_HMAC_MAX_KEY_SIZE = 64;
constexpr int SM3_HMAC_SIZE = 32;
constexpr int SM3_PBKDF2_MIN_ITER = 10000;
constexpr int SM3_PBKDF2_MAX_ITER = 16777216;
constexpr int SM3_PBKDF2_MAX_SALT_SIZE = 64;
constexpr int SM3_PBKDF2_DEFAULT_SALT_SIZE = 8;
constexpr int SM3_PBKDF2_MAX_KEY_SIZE = 256;

constexpr int SM4_KEY_SIZE = 16;
constexpr int SM4_BLOCK_SIZE = 16;
constexpr int SM4_CBC_IV_SIZE = 16;
constexpr int SM4_CTR_IV_SIZE = 16;
constexpr int SM4_GCM_MIN_IV_SIZE = 1;
constexpr int SM4_GCM_MAX_IV_SIZE = 64;
constexpr int SM4_GCM_DEFAULT_IV_SIZE = 12;
constexpr int SM4_GCM_DEFAULT_TAG_SIZE = 16;
constexpr int SM4_GCM_MAX_TAG_SIZE = 16;

static const char SM2_DEFAULT_ID[] = "1234567812345678";
constexpr int SM2_MAX_SIGNATURE_SIZE = 72;
constexpr int SM2_MIN_PLAINTEXT_SIZE = 1;
constexpr int SM2_MAX_PLAINTEXT_SIZE = 255;
constexpr int SM2_MIN_CIPHERTEXT_SIZE = 45;
constexpr int SM2_MAX_CIPHERTEXT_SIZE = 366;

constexpr int SM9_MAX_ID_SIZE = 63;
constexpr int SM9_MAX_PLAINTEXT_SIZE = 255;
constexpr int SM9_MAX_CIPHERTEXT_SIZE = 367;
constexpr int SM9_SIGNATURE_SIZE = 104;

constexpr int ZUC_KEY_SIZE = 16;
constexpr int ZUC_IV_SIZE = 16;

// ============================================================
// Helper functions / static references
// ============================================================

static Napi::FunctionReference g_sm2KeyCtor;

static void ThrowGmsslError(Napi::Env env) {
  Napi::Error::New(env, "GmSSL operation failed").ThrowAsJavaScriptException();
}

#define CHECK_GMSSL(env, ret) \
  do { if ((ret) != 1) { ThrowGmsslError(env); return env.Undefined(); } } while(0)

#define CHECK_GMSSL_BOOL(env, ret) \
  do { if ((ret) != 1) { ThrowGmsslError(env); return false; } } while(0)

inline Napi::Buffer<uint8_t> AllocBuffer(Napi::Env env, size_t size) {
  return Napi::Buffer<uint8_t>::New(env, size);
}

// ============================================================
// Forward declarations for classes that reference each other
// ============================================================

class Sm9SignKeyContext;
class Sm9EncKeyContext;
class Sm9SignMasterKeyContext;
class Sm9EncMasterKeyContext;

// ============================================================
// Version
// ============================================================

static Napi::Value VersionNum(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return Napi::Number::New(env, gmssl_version_num());
}

static Napi::Value VersionStr(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return Napi::String::New(env, gmssl_version_str());
}

// ============================================================
// Random
// ============================================================

static Napi::Value RandBytes(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Expected length (number)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  size_t length = info[0].As<Napi::Number>().Uint32Value();
  auto buf = AllocBuffer(env, length);
  if (rand_bytes(buf.Data(), length) != 1) {
    ThrowGmsslError(env);
  }
  return buf;
}

// ============================================================
// SM3 - Hash
// ============================================================

class Sm3Context : public Napi::ObjectWrap<Sm3Context> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm3Context(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value Digest(const Napi::CallbackInfo& info);
  Napi::Value Reset(const Napi::CallbackInfo& info);
  SM3_CTX ctx_;
};

Sm3Context::Sm3Context(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Sm3Context>(info) {
  sm3_init(&ctx_);
}

Napi::Object Sm3Context::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm3Context", {
    InstanceMethod("init", &Sm3Context::Init),
    InstanceMethod("update", &Sm3Context::Update),
    InstanceMethod("digest", &Sm3Context::Digest),
    InstanceMethod("reset", &Sm3Context::Reset),
  });
  exports.Set("Sm3Context", func);
  return exports;
}

Napi::Value Sm3Context::Init(const Napi::CallbackInfo& info) {
  sm3_init(&ctx_);
  return info.Env().Undefined();
}

Napi::Value Sm3Context::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  sm3_update(&ctx_, data.Data(), data.Length());
  return env.Undefined();
}

Napi::Value Sm3Context::Digest(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto buf = AllocBuffer(env, SM3_DIGEST_SIZE);
  sm3_finish(&ctx_, buf.Data());
  sm3_init(&ctx_);
  return buf;
}

Napi::Value Sm3Context::Reset(const Napi::CallbackInfo& info) {
  sm3_init(&ctx_);
  return info.Env().Undefined();
}

// ============================================================
// SM3 - HMAC
// ============================================================

class Sm3HmacContext : public Napi::ObjectWrap<Sm3HmacContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm3HmacContext(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value GenerateMac(const Napi::CallbackInfo& info);
  Napi::Value Reset(const Napi::CallbackInfo& info);
  SM3_HMAC_CTX ctx_;
  std::vector<uint8_t> key_;
};

Sm3HmacContext::Sm3HmacContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm3HmacContext>(info) {}

Napi::Object Sm3HmacContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm3HmacContext", {
    InstanceMethod("init", &Sm3HmacContext::Init),
    InstanceMethod("update", &Sm3HmacContext::Update),
    InstanceMethod("generateMac", &Sm3HmacContext::GenerateMac),
    InstanceMethod("reset", &Sm3HmacContext::Reset),
  });
  exports.Set("Sm3HmacContext", func);
  return exports;
}

Napi::Value Sm3HmacContext::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected key (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = info[0].As<Napi::Buffer<uint8_t>>();
  if (key.Length() < SM3_HMAC_MIN_KEY_SIZE || key.Length() > SM3_HMAC_MAX_KEY_SIZE) {
    Napi::Error::New(env, "Invalid key length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  key_.assign(key.Data(), key.Data() + key.Length());
  sm3_hmac_init(&ctx_, key.Data(), key.Length());
  return env.Undefined();
}

Napi::Value Sm3HmacContext::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  sm3_hmac_update(&ctx_, data.Data(), data.Length());
  return env.Undefined();
}

Napi::Value Sm3HmacContext::GenerateMac(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto mac = AllocBuffer(env, SM3_HMAC_SIZE);
  sm3_hmac_finish(&ctx_, mac.Data());
  sm3_hmac_init(&ctx_, key_.data(), key_.size());
  return mac;
}

Napi::Value Sm3HmacContext::Reset(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected key (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = info[0].As<Napi::Buffer<uint8_t>>();
  if (key.Length() < SM3_HMAC_MIN_KEY_SIZE || key.Length() > SM3_HMAC_MAX_KEY_SIZE) {
    Napi::Error::New(env, "Invalid key length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  key_.assign(key.Data(), key.Data() + key.Length());
  sm3_hmac_init(&ctx_, key.Data(), key.Length());
  return env.Undefined();
}

// ============================================================
// SM3 - PBKDF2
// ============================================================

static Napi::Value Sm3Pbkdf2(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4 || !info[0].IsString() || !info[1].IsBuffer()
      || !info[2].IsNumber() || !info[3].IsNumber()) {
    Napi::TypeError::New(env, "Expected (pass, salt, iter, keylen)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string pass = info[0].As<Napi::String>().Utf8Value();
  auto salt = info[1].As<Napi::Buffer<uint8_t>>();
  uint32_t iter = info[2].As<Napi::Number>().Uint32Value();
  uint32_t keylen = info[3].As<Napi::Number>().Uint32Value();
  if (salt.Length() > SM3_PBKDF2_MAX_SALT_SIZE) {
    Napi::Error::New(env, "Invalid salt size").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = AllocBuffer(env, keylen);
  if (sm3_pbkdf2(pass.c_str(), pass.size(), salt.Data(), salt.Length(),
        iter, keylen, key.Data()) != 1) {
    ThrowGmsslError(env);
  }
  return key;
}

// ============================================================
// SM4 - Block Cipher (ECB)
// ============================================================

class Sm4Context : public Napi::ObjectWrap<Sm4Context> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm4Context(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Encrypt(const Napi::CallbackInfo& info);
  SM4_KEY key_;
  bool encrypt_;
};

Sm4Context::Sm4Context(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm4Context>(info), encrypt_(true) {}

Napi::Object Sm4Context::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm4Context", {
    InstanceMethod("init", &Sm4Context::Init),
    InstanceMethod("encrypt", &Sm4Context::Encrypt),
  });
  exports.Set("Sm4Context", func);
  return exports;
}

Napi::Value Sm4Context::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBoolean()) {
    Napi::TypeError::New(env, "Expected (key, encrypt)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = info[0].As<Napi::Buffer<uint8_t>>();
  if (key.Length() != SM4_KEY_SIZE) {
    Napi::Error::New(env, "Invalid key length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  encrypt_ = info[1].As<Napi::Boolean>().Value();
  if (encrypt_) sm4_set_encrypt_key(&key_, key.Data());
  else sm4_set_decrypt_key(&key_, key.Data());
  return env.Undefined();
}

Napi::Value Sm4Context::Encrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected block (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto block = info[0].As<Napi::Buffer<uint8_t>>();
  if (block.Length() != SM4_BLOCK_SIZE) {
    Napi::Error::New(env, "Invalid block size").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto out = AllocBuffer(env, SM4_BLOCK_SIZE);
  sm4_encrypt(&key_, block.Data(), out.Data());
  return out;
}

// ============================================================
// SM4 - CBC
// ============================================================

class Sm4CbcContext : public Napi::ObjectWrap<Sm4CbcContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm4CbcContext(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value Finish(const Napi::CallbackInfo& info);
  SM4_CBC_CTX ctx_;
  bool encrypt_;
};

Sm4CbcContext::Sm4CbcContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm4CbcContext>(info), encrypt_(true) {}

Napi::Object Sm4CbcContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm4CbcContext", {
    InstanceMethod("init", &Sm4CbcContext::Init),
    InstanceMethod("update", &Sm4CbcContext::Update),
    InstanceMethod("finish", &Sm4CbcContext::Finish),
  });
  exports.Set("Sm4CbcContext", func);
  return exports;
}

Napi::Value Sm4CbcContext::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsBoolean()) {
    Napi::TypeError::New(env, "Expected (key, iv, encrypt)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = info[0].As<Napi::Buffer<uint8_t>>();
  auto iv = info[1].As<Napi::Buffer<uint8_t>>();
  encrypt_ = info[2].As<Napi::Boolean>().Value();
  if (key.Length() != SM4_KEY_SIZE) {
    Napi::Error::New(env, "Invalid key length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (iv.Length() != SM4_CBC_IV_SIZE) {
    Napi::Error::New(env, "Invalid IV length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (encrypt_) CHECK_GMSSL(env, sm4_cbc_encrypt_init(&ctx_, key.Data(), iv.Data()));
  else CHECK_GMSSL(env, sm4_cbc_decrypt_init(&ctx_, key.Data(), iv.Data()));
  return env.Undefined();
}

Napi::Value Sm4CbcContext::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  auto out = AllocBuffer(env, data.Length() + SM4_BLOCK_SIZE);
  size_t outlen = 0;
  if (encrypt_) CHECK_GMSSL(env, sm4_cbc_encrypt_update(&ctx_, data.Data(), data.Length(), out.Data(), &outlen));
  else CHECK_GMSSL(env, sm4_cbc_decrypt_update(&ctx_, data.Data(), data.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

Napi::Value Sm4CbcContext::Finish(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto out = AllocBuffer(env, SM4_BLOCK_SIZE);
  size_t outlen = 0;
  if (encrypt_) CHECK_GMSSL(env, sm4_cbc_encrypt_finish(&ctx_, out.Data(), &outlen));
  else CHECK_GMSSL(env, sm4_cbc_decrypt_finish(&ctx_, out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

// ============================================================
// SM4 - CTR
// ============================================================

class Sm4CtrContext : public Napi::ObjectWrap<Sm4CtrContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm4CtrContext(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value Finish(const Napi::CallbackInfo& info);
  SM4_CTR_CTX ctx_;
};

Sm4CtrContext::Sm4CtrContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm4CtrContext>(info) {}

Napi::Object Sm4CtrContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm4CtrContext", {
    InstanceMethod("init", &Sm4CtrContext::Init),
    InstanceMethod("update", &Sm4CtrContext::Update),
    InstanceMethod("finish", &Sm4CtrContext::Finish),
  });
  exports.Set("Sm4CtrContext", func);
  return exports;
}

Napi::Value Sm4CtrContext::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (key, iv)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = info[0].As<Napi::Buffer<uint8_t>>();
  auto iv = info[1].As<Napi::Buffer<uint8_t>>();
  if (key.Length() != SM4_KEY_SIZE) {
    Napi::Error::New(env, "Invalid key length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (iv.Length() != SM4_CTR_IV_SIZE) {
    Napi::Error::New(env, "Invalid IV length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  CHECK_GMSSL(env, sm4_ctr_encrypt_init(&ctx_, key.Data(), iv.Data()));
  return env.Undefined();
}

Napi::Value Sm4CtrContext::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  auto out = AllocBuffer(env, data.Length() + SM4_BLOCK_SIZE);
  size_t outlen = 0;
  CHECK_GMSSL(env, sm4_ctr_encrypt_update(&ctx_, data.Data(), data.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

Napi::Value Sm4CtrContext::Finish(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto out = AllocBuffer(env, SM4_BLOCK_SIZE);
  size_t outlen = 0;
  CHECK_GMSSL(env, sm4_ctr_encrypt_finish(&ctx_, out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

// ============================================================
// SM4 - GCM
// ============================================================

class Sm4GcmContext : public Napi::ObjectWrap<Sm4GcmContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm4GcmContext(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value Finish(const Napi::CallbackInfo& info);
  SM4_GCM_CTX ctx_;
  bool encrypt_;
  int taglen_;
};

Sm4GcmContext::Sm4GcmContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm4GcmContext>(info), encrypt_(true), taglen_(16) {}

Napi::Object Sm4GcmContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm4GcmContext", {
    InstanceMethod("init", &Sm4GcmContext::Init),
    InstanceMethod("update", &Sm4GcmContext::Update),
    InstanceMethod("finish", &Sm4GcmContext::Finish),
  });
  exports.Set("Sm4GcmContext", func);
  return exports;
}

Napi::Value Sm4GcmContext::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 5 || !info[0].IsBuffer() || !info[1].IsBuffer()
      || !info[2].IsBuffer() || !info[3].IsNumber() || !info[4].IsBoolean()) {
    Napi::TypeError::New(env, "Expected (key, iv, aad, taglen, encrypt)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = info[0].As<Napi::Buffer<uint8_t>>();
  auto iv = info[1].As<Napi::Buffer<uint8_t>>();
  auto aad = info[2].As<Napi::Buffer<uint8_t>>();
  taglen_ = info[3].As<Napi::Number>().Int32Value();
  encrypt_ = info[4].As<Napi::Boolean>().Value();
  if (key.Length() != SM4_KEY_SIZE) {
    Napi::Error::New(env, "Invalid key length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (taglen_ > SM4_GCM_MAX_TAG_SIZE) {
    Napi::Error::New(env, "Invalid tag length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (encrypt_) {
    CHECK_GMSSL(env, sm4_gcm_encrypt_init(&ctx_, key.Data(), key.Length(),
      iv.Data(), iv.Length(), aad.Data(), aad.Length(), taglen_));
  } else {
    CHECK_GMSSL(env, sm4_gcm_decrypt_init(&ctx_, key.Data(), key.Length(),
      iv.Data(), iv.Length(), aad.Data(), aad.Length(), taglen_));
  }
  return env.Undefined();
}

Napi::Value Sm4GcmContext::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  auto out = AllocBuffer(env, data.Length() + SM4_BLOCK_SIZE);
  size_t outlen = 0;
  if (encrypt_) CHECK_GMSSL(env, sm4_gcm_encrypt_update(&ctx_, data.Data(), data.Length(), out.Data(), &outlen));
  else CHECK_GMSSL(env, sm4_gcm_decrypt_update(&ctx_, data.Data(), data.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

Napi::Value Sm4GcmContext::Finish(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  size_t outlen = 0;
  if (encrypt_) {
    auto out = AllocBuffer(env, SM4_BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE);
    CHECK_GMSSL(env, sm4_gcm_encrypt_finish(&ctx_, out.Data(), &outlen));
    return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
  } else {
    auto out = AllocBuffer(env, SM4_BLOCK_SIZE);
    CHECK_GMSSL(env, sm4_gcm_decrypt_finish(&ctx_, out.Data(), &outlen));
    return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
  }
}

// ============================================================
// ZUC
// ============================================================

class ZucContext : public Napi::ObjectWrap<ZucContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  ZucContext(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value Finish(const Napi::CallbackInfo& info);
  ZUC_CTX ctx_;
};

ZucContext::ZucContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<ZucContext>(info) {}

Napi::Object ZucContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "ZucContext", {
    InstanceMethod("init", &ZucContext::Init),
    InstanceMethod("update", &ZucContext::Update),
    InstanceMethod("finish", &ZucContext::Finish),
  });
  exports.Set("ZucContext", func);
  return exports;
}

Napi::Value ZucContext::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (key, iv)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto key = info[0].As<Napi::Buffer<uint8_t>>();
  auto iv = info[1].As<Napi::Buffer<uint8_t>>();
  if (key.Length() != ZUC_KEY_SIZE) {
    Napi::Error::New(env, "Invalid key length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (iv.Length() != ZUC_IV_SIZE) {
    Napi::Error::New(env, "Invalid IV length").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  CHECK_GMSSL(env, zuc_encrypt_init(&ctx_, key.Data(), iv.Data()));
  return env.Undefined();
}

Napi::Value ZucContext::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  auto out = AllocBuffer(env, data.Length() + 16);
  size_t outlen = 0;
  CHECK_GMSSL(env, zuc_encrypt_update(&ctx_, data.Data(), data.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

Napi::Value ZucContext::Finish(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto out = AllocBuffer(env, 16);
  size_t outlen = 0;
  CHECK_GMSSL(env, zuc_encrypt_finish(&ctx_, out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

// ============================================================
// SM2 - Key Context
// ============================================================

class Sm2KeyContext : public Napi::ObjectWrap<Sm2KeyContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm2KeyContext(const Napi::CallbackInfo& info);

  // Public for access by Sm2SignatureContext and certificate functions
  SM2_KEY key_;
  bool has_private_key_;

private:
  Napi::Value GenerateKey(const Napi::CallbackInfo& info);
  Napi::Value ImportPrivateKeyInfoDer(const Napi::CallbackInfo& info);
  Napi::Value ExportPrivateKeyInfoDer(const Napi::CallbackInfo& info);
  Napi::Value ImportPublicKeyInfoDer(const Napi::CallbackInfo& info);
  Napi::Value ExportPublicKeyInfoDer(const Napi::CallbackInfo& info);
  Napi::Value ImportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ExportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ImportPublicKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ExportPublicKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ComputeZ(const Napi::CallbackInfo& info);
  Napi::Value Sign(const Napi::CallbackInfo& info);
  Napi::Value Verify(const Napi::CallbackInfo& info);
  Napi::Value Encrypt(const Napi::CallbackInfo& info);
  Napi::Value Decrypt(const Napi::CallbackInfo& info);
};

Sm2KeyContext::Sm2KeyContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm2KeyContext>(info), has_private_key_(false) {
  memset(&key_, 0, sizeof(key_));
}

Napi::Object Sm2KeyContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm2KeyContext", {
    InstanceMethod("generateKey", &Sm2KeyContext::GenerateKey),
    InstanceMethod("importPrivateKeyInfoDer", &Sm2KeyContext::ImportPrivateKeyInfoDer),
    InstanceMethod("exportPrivateKeyInfoDer", &Sm2KeyContext::ExportPrivateKeyInfoDer),
    InstanceMethod("importPublicKeyInfoDer", &Sm2KeyContext::ImportPublicKeyInfoDer),
    InstanceMethod("exportPublicKeyInfoDer", &Sm2KeyContext::ExportPublicKeyInfoDer),
    InstanceMethod("importEncryptedPrivateKeyInfoPem", &Sm2KeyContext::ImportEncryptedPrivateKeyInfoPem),
    InstanceMethod("exportEncryptedPrivateKeyInfoPem", &Sm2KeyContext::ExportEncryptedPrivateKeyInfoPem),
    InstanceMethod("importPublicKeyInfoPem", &Sm2KeyContext::ImportPublicKeyInfoPem),
    InstanceMethod("exportPublicKeyInfoPem", &Sm2KeyContext::ExportPublicKeyInfoPem),
    InstanceMethod("computeZ", &Sm2KeyContext::ComputeZ),
    InstanceMethod("sign", &Sm2KeyContext::Sign),
    InstanceMethod("verify", &Sm2KeyContext::Verify),
    InstanceMethod("encrypt", &Sm2KeyContext::Encrypt),
    InstanceMethod("decrypt", &Sm2KeyContext::Decrypt),
  });
  exports.Set("Sm2KeyContext", func);
  return exports;
}

Napi::Value Sm2KeyContext::GenerateKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  CHECK_GMSSL(env, sm2_key_generate(&key_));
  has_private_key_ = true;
  return env.Undefined();
}

Napi::Value Sm2KeyContext::ImportPrivateKeyInfoDer(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected DER data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto buf = info[0].As<Napi::Buffer<uint8_t>>();
  const uint8_t* data = buf.Data();
  size_t datalen = buf.Length();
  // sm2_private_key_info_from_der requires non-null attrs/attrslen (asn1_type_from_der checks)
  const uint8_t* attrs = nullptr;
  size_t attrslen = 0;
  if (sm2_private_key_info_from_der(&key_, &attrs, &attrslen, &data, &datalen) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  has_private_key_ = true;
  return env.Undefined();
}

Napi::Value Sm2KeyContext::ExportPrivateKeyInfoDer(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  // GmSSL 3.1 requires pre-allocated buffer (like sm2_public_key_info_to_pem uses buf[512])
  uint8_t buf[512];
  uint8_t* p = buf;
  size_t outlen = 0;
  if (sm2_private_key_info_to_der(&key_, &p, &outlen) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  return Napi::Buffer<uint8_t>::Copy(env, buf, outlen);
}

Napi::Value Sm2KeyContext::ImportPublicKeyInfoDer(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected DER data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto buf = info[0].As<Napi::Buffer<uint8_t>>();
  const uint8_t* data = buf.Data();
  size_t datalen = buf.Length();
  // sm2_public_key_info_from_der(key, in, inlen) - GmSSL 3.1 API
  if (sm2_public_key_info_from_der(&key_, &data, &datalen) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  has_private_key_ = false;
  return env.Undefined();
}

Napi::Value Sm2KeyContext::ExportPublicKeyInfoDer(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  // GmSSL 3.1 requires pre-allocated buffer
  uint8_t buf[512];
  uint8_t* p = buf;
  size_t outlen = 0;
  if (sm2_public_key_info_to_der(&key_, &p, &outlen) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  return Napi::Buffer<uint8_t>::Copy(env, buf, outlen);
}

Napi::Value Sm2KeyContext::ImportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (password, path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string pass = info[0].As<Napi::String>().Utf8Value();
  std::string path = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm2_private_key_info_decrypt_from_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  has_private_key_ = true;
  return env.Undefined();
}

Napi::Value Sm2KeyContext::ExportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (password, path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string pass = info[0].As<Napi::String>().Utf8Value();
  std::string path = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm2_private_key_info_encrypt_to_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

Napi::Value Sm2KeyContext::ImportPublicKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm2_public_key_info_from_pem(&key_, fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  has_private_key_ = false;
  return env.Undefined();
}

Napi::Value Sm2KeyContext::ExportPublicKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm2_public_key_info_to_pem(&key_, fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

Napi::Value Sm2KeyContext::ComputeZ(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (id)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string id = info[0].As<Napi::String>().Utf8Value();
  auto z = AllocBuffer(env, SM3_DIGEST_SIZE);
  CHECK_GMSSL(env, sm2_compute_z(z.Data(), &key_.public_key, id.c_str(), id.size()));
  return z;
}

Napi::Value Sm2KeyContext::Sign(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected digest (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto dgst = info[0].As<Napi::Buffer<uint8_t>>();
  if (dgst.Length() != SM3_DIGEST_SIZE) {
    Napi::Error::New(env, "Invalid digest size").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto sig = AllocBuffer(env, SM2_MAX_SIGNATURE_SIZE);
  size_t siglen = 0;
  CHECK_GMSSL(env, sm2_sign(&key_, dgst.Data(), sig.Data(), &siglen));
  return Napi::Buffer<uint8_t>::Copy(env, sig.Data(), siglen);
}

Napi::Value Sm2KeyContext::Verify(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (digest, signature)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto dgst = info[0].As<Napi::Buffer<uint8_t>>();
  auto sig = info[1].As<Napi::Buffer<uint8_t>>();
  if (dgst.Length() != SM3_DIGEST_SIZE) return Napi::Boolean::New(env, false);
  int ret = sm2_verify(&key_, dgst.Data(), sig.Data(), sig.Length());
  return Napi::Boolean::New(env, ret == 1);
}

Napi::Value Sm2KeyContext::Encrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected plaintext (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto plaintext = info[0].As<Napi::Buffer<uint8_t>>();
  auto out = AllocBuffer(env, SM2_MAX_CIPHERTEXT_SIZE);
  size_t outlen = 0;
  CHECK_GMSSL(env, sm2_encrypt(&key_, plaintext.Data(), plaintext.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

Napi::Value Sm2KeyContext::Decrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected ciphertext (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto ciphertext = info[0].As<Napi::Buffer<uint8_t>>();
  auto out = AllocBuffer(env, SM2_MAX_PLAINTEXT_SIZE);
  size_t outlen = 0;
  CHECK_GMSSL(env, sm2_decrypt(&key_, ciphertext.Data(), ciphertext.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

// ============================================================
// SM2 - Signature Context (streaming sign/verify)
// Uses SM2_SIGN_CTX and SM2_VERIFY_CTX separately (GmSSL 3.1.3+)
// ============================================================

class Sm2SignatureContext : public Napi::ObjectWrap<Sm2SignatureContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm2SignatureContext(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value Sign(const Napi::CallbackInfo& info);
  Napi::Value Verify(const Napi::CallbackInfo& info);

  SM2_SIGN_CTX sign_ctx_;
  SM2_VERIFY_CTX verify_ctx_;
  bool do_sign_;
  bool initialized_;
};

Sm2SignatureContext::Sm2SignatureContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm2SignatureContext>(info), do_sign_(true), initialized_(false) {
  memset(&sign_ctx_, 0, sizeof(sign_ctx_));
  memset(&verify_ctx_, 0, sizeof(verify_ctx_));
}

Napi::Object Sm2SignatureContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm2SignatureContext", {
    InstanceMethod("init", &Sm2SignatureContext::Init),
    InstanceMethod("update", &Sm2SignatureContext::Update),
    InstanceMethod("sign", &Sm2SignatureContext::Sign),
    InstanceMethod("verify", &Sm2SignatureContext::Verify),
  });
  exports.Set("Sm2SignatureContext", func);
  return exports;
}

Napi::Value Sm2SignatureContext::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsObject() || !info[1].IsString() || !info[2].IsBoolean()) {
    Napi::TypeError::New(env, "Expected (key, id, doSign)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  Sm2KeyContext* key_ctx = Sm2KeyContext::Unwrap(info[0].As<Napi::Object>());
  std::string id = info[1].As<Napi::String>().Utf8Value();
  do_sign_ = info[2].As<Napi::Boolean>().Value();

  if (do_sign_) {
    if (!key_ctx->has_private_key_) {
      Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    CHECK_GMSSL(env, sm2_sign_init(&sign_ctx_, &key_ctx->key_, id.c_str(), id.size()));
  } else {
    CHECK_GMSSL(env, sm2_verify_init(&verify_ctx_, &key_ctx->key_, id.c_str(), id.size()));
  }
  initialized_ = true;
  return env.Undefined();
}

Napi::Value Sm2SignatureContext::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  if (data.Length() == 0) return env.Undefined();
  if (do_sign_) CHECK_GMSSL(env, sm2_sign_update(&sign_ctx_, data.Data(), data.Length()));
  else CHECK_GMSSL(env, sm2_verify_update(&verify_ctx_, data.Data(), data.Length()));
  return env.Undefined();
}

Napi::Value Sm2SignatureContext::Sign(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!do_sign_) {
    Napi::Error::New(env, "Not in signing state").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto sig = AllocBuffer(env, SM2_MAX_SIGNATURE_SIZE);
  size_t siglen = 0;
  CHECK_GMSSL(env, sm2_sign_finish(&sign_ctx_, sig.Data(), &siglen));
  return Napi::Buffer<uint8_t>::Copy(env, sig.Data(), siglen);
}

Napi::Value Sm2SignatureContext::Verify(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (do_sign_) {
    Napi::Error::New(env, "Not in verification state").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected signature (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto sig = info[0].As<Napi::Buffer<uint8_t>>();
  int ret = sm2_verify_finish(&verify_ctx_, sig.Data(), sig.Length());
  return Napi::Boolean::New(env, ret == 1);
}

// ============================================================
// SM9 - Signature Key (forward declaration needed)
// ============================================================

class Sm9SignKeyContext : public Napi::ObjectWrap<Sm9SignKeyContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  static Napi::Function GetClass(Napi::Env env);
  Sm9SignKeyContext(const Napi::CallbackInfo& info);

  SM9_SIGN_KEY key_;
  std::string id_;
  bool initialized_;

private:
  Napi::Value GetId(const Napi::CallbackInfo& info);
  Napi::Value ImportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ExportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info);
};

Napi::Function Sm9SignKeyContext::GetClass(Napi::Env env) {
  return DefineClass(env, "Sm9SignKeyContext", {
    InstanceMethod("getId", &Sm9SignKeyContext::GetId),
    InstanceMethod("importEncryptedPrivateKeyInfoPem", &Sm9SignKeyContext::ImportEncryptedPrivateKeyInfoPem),
    InstanceMethod("exportEncryptedPrivateKeyInfoPem", &Sm9SignKeyContext::ExportEncryptedPrivateKeyInfoPem),
  });
}

Sm9SignKeyContext::Sm9SignKeyContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm9SignKeyContext>(info), initialized_(false) {
  memset(&key_, 0, sizeof(key_));
}

Napi::Object Sm9SignKeyContext::Init(Napi::Env env, Napi::Object exports) {
  exports.Set("Sm9SignKeyContext", GetClass(env));
  return exports;
}

Napi::Value Sm9SignKeyContext::GetId(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), id_);
}

Napi::Value Sm9SignKeyContext::ImportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_sign_key_info_decrypt_from_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  initialized_ = true;
  return env.Undefined();
}

Napi::Value Sm9SignKeyContext::ExportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_sign_key_info_encrypt_to_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

// ============================================================
// SM9 - Sign Master Key
// ============================================================

class Sm9SignMasterKeyContext : public Napi::ObjectWrap<Sm9SignMasterKeyContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm9SignMasterKeyContext(const Napi::CallbackInfo& info);

  SM9_SIGN_MASTER_KEY key_;
  bool has_private_key_;

private:
  Napi::Value GenerateMasterKey(const Napi::CallbackInfo& info);
  Napi::Value ImportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ExportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ImportPublicMasterKeyPem(const Napi::CallbackInfo& info);
  Napi::Value ExportPublicMasterKeyPem(const Napi::CallbackInfo& info);
  Napi::Value ExtractKey(const Napi::CallbackInfo& info);
};

Sm9SignMasterKeyContext::Sm9SignMasterKeyContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm9SignMasterKeyContext>(info), has_private_key_(false) {
  memset(&key_, 0, sizeof(key_));
}

Napi::Object Sm9SignMasterKeyContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm9SignMasterKeyContext", {
    InstanceMethod("generateMasterKey", &Sm9SignMasterKeyContext::GenerateMasterKey),
    InstanceMethod("importEncryptedMasterKeyInfoPem", &Sm9SignMasterKeyContext::ImportEncryptedMasterKeyInfoPem),
    InstanceMethod("exportEncryptedMasterKeyInfoPem", &Sm9SignMasterKeyContext::ExportEncryptedMasterKeyInfoPem),
    InstanceMethod("importPublicMasterKeyPem", &Sm9SignMasterKeyContext::ImportPublicMasterKeyPem),
    InstanceMethod("exportPublicMasterKeyPem", &Sm9SignMasterKeyContext::ExportPublicMasterKeyPem),
    InstanceMethod("extractKey", &Sm9SignMasterKeyContext::ExtractKey),
  });
  exports.Set("Sm9SignMasterKeyContext", func);
  return exports;
}

Napi::Value Sm9SignMasterKeyContext::GenerateMasterKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  CHECK_GMSSL(env, sm9_sign_master_key_generate(&key_));
  has_private_key_ = true;
  return env.Undefined();
}

Napi::Value Sm9SignMasterKeyContext::ImportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_sign_master_key_info_decrypt_from_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  has_private_key_ = true;
  return env.Undefined();
}

Napi::Value Sm9SignMasterKeyContext::ExportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_sign_master_key_info_encrypt_to_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

Napi::Value Sm9SignMasterKeyContext::ImportPublicMasterKeyPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_sign_master_public_key_from_pem(&key_, fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  has_private_key_ = false;
  return env.Undefined();
}

Napi::Value Sm9SignMasterKeyContext::ExportPublicMasterKeyPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_sign_master_public_key_to_pem(&key_, fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

Napi::Value Sm9SignMasterKeyContext::ExtractKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (id)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string id = info[0].As<Napi::String>().Utf8Value();

  Napi::Object obj = Sm9SignKeyContext::GetClass(env).New({});
  Sm9SignKeyContext* wrapped = Sm9SignKeyContext::Unwrap(obj);
  CHECK_GMSSL(env, sm9_sign_master_key_extract_key(&key_, id.c_str(), id.size(), &wrapped->key_));
  wrapped->id_ = id;
  wrapped->initialized_ = true;
  return obj;
}

// ============================================================
// SM9 - Encryption Key
// ============================================================

class Sm9EncKeyContext : public Napi::ObjectWrap<Sm9EncKeyContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  static Napi::Function GetClass(Napi::Env env);
  Sm9EncKeyContext(const Napi::CallbackInfo& info);

  SM9_ENC_KEY key_;
  std::string id_;
  bool initialized_;

private:
  Napi::Value GetId(const Napi::CallbackInfo& info);
  Napi::Value ImportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ExportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value Decrypt(const Napi::CallbackInfo& info);
};

Napi::Function Sm9EncKeyContext::GetClass(Napi::Env env) {
  return DefineClass(env, "Sm9EncKeyContext", {
    InstanceMethod("getId", &Sm9EncKeyContext::GetId),
    InstanceMethod("importEncryptedPrivateKeyInfoPem", &Sm9EncKeyContext::ImportEncryptedPrivateKeyInfoPem),
    InstanceMethod("exportEncryptedPrivateKeyInfoPem", &Sm9EncKeyContext::ExportEncryptedPrivateKeyInfoPem),
    InstanceMethod("decrypt", &Sm9EncKeyContext::Decrypt),
  });
}

Sm9EncKeyContext::Sm9EncKeyContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm9EncKeyContext>(info), initialized_(false) {
  memset(&key_, 0, sizeof(key_));
}

Napi::Object Sm9EncKeyContext::Init(Napi::Env env, Napi::Object exports) {
  exports.Set("Sm9EncKeyContext", GetClass(env));
  return exports;
}

Napi::Value Sm9EncKeyContext::GetId(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), id_);
}

Napi::Value Sm9EncKeyContext::ImportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_enc_key_info_decrypt_from_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  initialized_ = true;
  return env.Undefined();
}

Napi::Value Sm9EncKeyContext::ExportEncryptedPrivateKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_enc_key_info_encrypt_to_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

Napi::Value Sm9EncKeyContext::Decrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected ciphertext (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto ciphertext = info[0].As<Napi::Buffer<uint8_t>>();
  auto out = AllocBuffer(env, SM9_MAX_PLAINTEXT_SIZE);
  size_t outlen = 0;
  CHECK_GMSSL(env, sm9_decrypt(&key_, id_.c_str(), id_.size(),
    ciphertext.Data(), ciphertext.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

// ============================================================
// SM9 - Encryption Master Key
// ============================================================

class Sm9EncMasterKeyContext : public Napi::ObjectWrap<Sm9EncMasterKeyContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm9EncMasterKeyContext(const Napi::CallbackInfo& info);

  SM9_ENC_MASTER_KEY key_;
  bool has_private_key_;

private:
  Napi::Value GenerateMasterKey(const Napi::CallbackInfo& info);
  Napi::Value ImportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ExportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info);
  Napi::Value ImportPublicMasterKeyPem(const Napi::CallbackInfo& info);
  Napi::Value ExportPublicMasterKeyPem(const Napi::CallbackInfo& info);
  Napi::Value ExtractKey(const Napi::CallbackInfo& info);
  Napi::Value Encrypt(const Napi::CallbackInfo& info);
};

Sm9EncMasterKeyContext::Sm9EncMasterKeyContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm9EncMasterKeyContext>(info), has_private_key_(false) {
  memset(&key_, 0, sizeof(key_));
}

Napi::Object Sm9EncMasterKeyContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm9EncMasterKeyContext", {
    InstanceMethod("generateMasterKey", &Sm9EncMasterKeyContext::GenerateMasterKey),
    InstanceMethod("importEncryptedMasterKeyInfoPem", &Sm9EncMasterKeyContext::ImportEncryptedMasterKeyInfoPem),
    InstanceMethod("exportEncryptedMasterKeyInfoPem", &Sm9EncMasterKeyContext::ExportEncryptedMasterKeyInfoPem),
    InstanceMethod("importPublicMasterKeyPem", &Sm9EncMasterKeyContext::ImportPublicMasterKeyPem),
    InstanceMethod("exportPublicMasterKeyPem", &Sm9EncMasterKeyContext::ExportPublicMasterKeyPem),
    InstanceMethod("extractKey", &Sm9EncMasterKeyContext::ExtractKey),
    InstanceMethod("encrypt", &Sm9EncMasterKeyContext::Encrypt),
  });
  exports.Set("Sm9EncMasterKeyContext", func);
  return exports;
}

Napi::Value Sm9EncMasterKeyContext::GenerateMasterKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  CHECK_GMSSL(env, sm9_enc_master_key_generate(&key_));
  has_private_key_ = true;
  return env.Undefined();
}

Napi::Value Sm9EncMasterKeyContext::ImportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_enc_master_key_info_decrypt_from_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  has_private_key_ = true;
  return env.Undefined();
}

Napi::Value Sm9EncMasterKeyContext::ExportEncryptedMasterKeyInfoPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (path, pass)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  std::string pass = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_enc_master_key_info_encrypt_to_pem(&key_, pass.c_str(), fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

Napi::Value Sm9EncMasterKeyContext::ImportPublicMasterKeyPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_enc_master_public_key_from_pem(&key_, fp);
  fclose(fp);
  if (ret != 1) { ThrowGmsslError(env); return env.Undefined(); }
  has_private_key_ = false;
  return env.Undefined();
}

Napi::Value Sm9EncMasterKeyContext::ExportPublicMasterKeyPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = sm9_enc_master_public_key_to_pem(&key_, fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

Napi::Value Sm9EncMasterKeyContext::ExtractKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!has_private_key_) {
    Napi::Error::New(env, "Not a private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (id)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string id = info[0].As<Napi::String>().Utf8Value();

  Napi::Object obj = Sm9EncKeyContext::GetClass(env).New({});
  Sm9EncKeyContext* wrapped = Sm9EncKeyContext::Unwrap(obj);
  CHECK_GMSSL(env, sm9_enc_master_key_extract_key(&key_, id.c_str(), id.size(), &wrapped->key_));
  wrapped->id_ = id;
  wrapped->initialized_ = true;
  return obj;
}

Napi::Value Sm9EncMasterKeyContext::Encrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (plaintext, toId)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto plaintext = info[0].As<Napi::Buffer<uint8_t>>();
  std::string to_id = info[1].As<Napi::String>().Utf8Value();
  auto out = AllocBuffer(env, SM9_MAX_CIPHERTEXT_SIZE);
  size_t outlen = 0;
  CHECK_GMSSL(env, sm9_encrypt(&key_, to_id.c_str(), to_id.size(),
    plaintext.Data(), plaintext.Length(), out.Data(), &outlen));
  return Napi::Buffer<uint8_t>::Copy(env, out.Data(), outlen);
}

// ============================================================
// SM9 - Signature Context (streaming)
// ============================================================

class Sm9SignatureContext : public Napi::ObjectWrap<Sm9SignatureContext> {
public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  Sm9SignatureContext(const Napi::CallbackInfo& info);
private:
  Napi::Value Init(const Napi::CallbackInfo& info);
  Napi::Value Update(const Napi::CallbackInfo& info);
  Napi::Value Sign(const Napi::CallbackInfo& info);
  Napi::Value Verify(const Napi::CallbackInfo& info);
  SM9_SIGN_CTX ctx_;
  bool do_sign_;
};

Sm9SignatureContext::Sm9SignatureContext(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<Sm9SignatureContext>(info), do_sign_(true) {}

Napi::Object Sm9SignatureContext::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function func = DefineClass(env, "Sm9SignatureContext", {
    InstanceMethod("init", &Sm9SignatureContext::Init),
    InstanceMethod("update", &Sm9SignatureContext::Update),
    InstanceMethod("sign", &Sm9SignatureContext::Sign),
    InstanceMethod("verify", &Sm9SignatureContext::Verify),
  });
  exports.Set("Sm9SignatureContext", func);
  return exports;
}

Napi::Value Sm9SignatureContext::Init(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBoolean()) {
    Napi::TypeError::New(env, "Expected (doSign)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  do_sign_ = info[0].As<Napi::Boolean>().Value();
  if (do_sign_) CHECK_GMSSL(env, sm9_sign_init(&ctx_));
  else CHECK_GMSSL(env, sm9_verify_init(&ctx_));
  return env.Undefined();
}

Napi::Value Sm9SignatureContext::Update(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected data (Buffer)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto data = info[0].As<Napi::Buffer<uint8_t>>();
  if (data.Length() == 0) return env.Undefined();
  if (do_sign_) CHECK_GMSSL(env, sm9_sign_update(&ctx_, data.Data(), data.Length()));
  else CHECK_GMSSL(env, sm9_verify_update(&ctx_, data.Data(), data.Length()));
  return env.Undefined();
}

Napi::Value Sm9SignatureContext::Sign(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!do_sign_) {
    Napi::Error::New(env, "Not in signing state").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 1 || !info[0].IsObject()) {
    Napi::TypeError::New(env, "Expected (signKey)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  Sm9SignKeyContext* sign_key = Sm9SignKeyContext::Unwrap(info[0].As<Napi::Object>());
  auto sig = AllocBuffer(env, SM9_SIGNATURE_SIZE);
  size_t siglen = 0;
  CHECK_GMSSL(env, sm9_sign_finish(&ctx_, &sign_key->key_, sig.Data(), &siglen));
  return Napi::Buffer<uint8_t>::Copy(env, sig.Data(), siglen);
}

Napi::Value Sm9SignatureContext::Verify(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (do_sign_) {
    Napi::Error::New(env, "Not in verification state").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsObject() || !info[2].IsString()) {
    Napi::TypeError::New(env, "Expected (sig, masterPubKey, signerId)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto sig = info[0].As<Napi::Buffer<uint8_t>>();
  Sm9SignMasterKeyContext* master_pub = Sm9SignMasterKeyContext::Unwrap(info[1].As<Napi::Object>());
  std::string signer_id = info[2].As<Napi::String>().Utf8Value();
  int ret = sm9_verify_finish(&ctx_, sig.Data(), sig.Length(),
    &master_pub->key_, signer_id.c_str(), signer_id.size());
  return Napi::Boolean::New(env, ret == 1);
}

// ============================================================
// Certificate
// ============================================================

static Napi::Value CertFromPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "Expected (path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  std::string path = info[0].As<Napi::String>().Utf8Value();
  uint8_t* cert = nullptr;
  size_t certlen = 0;
  if (x509_cert_new_from_file(&cert, &certlen, path.c_str()) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  auto buf = Napi::Buffer<uint8_t>::Copy(env, cert, certlen);
  free(cert);
  return buf;
}

static Napi::Value CertToPem(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Expected (cert, path)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  std::string path = info[1].As<Napi::String>().Utf8Value();
  FILE* fp = fopen(path.c_str(), "wb");
  if (!fp) {
    Napi::Error::New(env, "fopen failure").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  int ret = x509_cert_to_pem(cert.Data(), cert.Length(), fp);
  fclose(fp);
  CHECK_GMSSL(env, ret);
  return env.Undefined();
}

static Napi::Value CertGetSerialNumber(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (cert)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  const uint8_t* serial = nullptr;
  size_t serial_len = 0;
  if (x509_cert_get_issuer_and_serial_number(cert.Data(), cert.Length(),
        nullptr, nullptr, &serial, &serial_len) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  return Napi::Buffer<uint8_t>::Copy(env, serial, serial_len);
}

static Napi::Value CertGetNotBefore(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (cert)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  time_t t_before = 0, t_after = 0;
  if (x509_cert_get_details(cert.Data(), cert.Length(),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        &t_before, &t_after,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  return Napi::Number::New(env, (double)t_before);
}

static Napi::Value CertGetNotAfter(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (cert)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  time_t t_before = 0, t_after = 0;
  if (x509_cert_get_details(cert.Data(), cert.Length(),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        &t_before, &t_after,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  return Napi::Number::New(env, (double)t_after);
}

static Napi::Value CertGetSubjectPublicKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (cert)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  // Use X509_KEY wrapper to extract the key, then get SM2_KEY from it
  X509_KEY xkey;
  memset(&xkey, 0, sizeof(xkey));
  if (x509_cert_get_subject_public_key(cert.Data(), cert.Length(), &xkey) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  // Create Sm2KeyContext and copy the SM2 key
  Napi::Object obj = g_sm2KeyCtor.Value().New({});
  Sm2KeyContext* sm2 = Sm2KeyContext::Unwrap(obj);
  sm2->key_ = xkey.u.sm2_key;
  sm2->has_private_key_ = false;
  return obj;
}

static Napi::Value CertVerifyByCaCert(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsString()) {
    Napi::TypeError::New(env, "Expected (cert, caCert, sm2Id)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  auto ca_cert = info[1].As<Napi::Buffer<uint8_t>>();
  std::string sm2_id = info[2].As<Napi::String>().Utf8Value();
  int ret = x509_cert_verify_by_ca_cert(cert.Data(), cert.Length(),
    ca_cert.Data(), ca_cert.Length(), sm2_id.c_str(), sm2_id.size());
  return Napi::Boolean::New(env, ret == 1);
}

static Napi::Value CertGetIssuer(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (cert)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  const uint8_t* issuer = nullptr;
  size_t issuer_len = 0;
  if (x509_cert_get_issuer(cert.Data(), cert.Length(), &issuer, &issuer_len) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  return Napi::Buffer<uint8_t>::Copy(env, issuer, issuer_len);
}

static Napi::Value CertGetSubject(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expected (cert)").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  auto cert = info[0].As<Napi::Buffer<uint8_t>>();
  const uint8_t* subject = nullptr;
  size_t subject_len = 0;
  if (x509_cert_get_subject(cert.Data(), cert.Length(), &subject, &subject_len) != 1) {
    ThrowGmsslError(env);
    return env.Undefined();
  }
  return Napi::Buffer<uint8_t>::Copy(env, subject, subject_len);
}

// ============================================================
// Module Initialization
// ============================================================

static Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
  // Version
  exports.Set("versionNum", Napi::Function::New(env, VersionNum));
  exports.Set("versionStr", Napi::Function::New(env, VersionStr));

  // Random
  exports.Set("randBytes", Napi::Function::New(env, RandBytes));

  // SM3
  Sm3Context::Init(env, exports);
  Sm3HmacContext::Init(env, exports);
  exports.Set("sm3Pbkdf2", Napi::Function::New(env, Sm3Pbkdf2));

  // SM4
  Sm4Context::Init(env, exports);
  Sm4CbcContext::Init(env, exports);
  Sm4CtrContext::Init(env, exports);
  Sm4GcmContext::Init(env, exports);

  // ZUC
  ZucContext::Init(env, exports);

  // SM2
  Sm2KeyContext::Init(env, exports);
  g_sm2KeyCtor = Napi::Persistent(exports.Get("Sm2KeyContext").As<Napi::Function>());
  Sm2SignatureContext::Init(env, exports);

  // SM9
  Sm9SignMasterKeyContext::Init(env, exports);
  Sm9SignKeyContext::Init(env, exports);
  Sm9EncMasterKeyContext::Init(env, exports);
  Sm9EncKeyContext::Init(env, exports);
  Sm9SignatureContext::Init(env, exports);

  // Certificate
  exports.Set("certFromPem", Napi::Function::New(env, CertFromPem));
  exports.Set("certToPem", Napi::Function::New(env, CertToPem));
  exports.Set("certGetSerialNumber", Napi::Function::New(env, CertGetSerialNumber));
  exports.Set("certGetNotBefore", Napi::Function::New(env, CertGetNotBefore));
  exports.Set("certGetNotAfter", Napi::Function::New(env, CertGetNotAfter));
  exports.Set("certGetSubjectPublicKey", Napi::Function::New(env, CertGetSubjectPublicKey));
  exports.Set("certVerifyByCaCert", Napi::Function::New(env, CertVerifyByCaCert));
  exports.Set("certGetIssuer", Napi::Function::New(env, CertGetIssuer));
  exports.Set("certGetSubject", Napi::Function::New(env, CertGetSubject));

  // JS-visible constants
  exports.Set("SM3_DIGEST_SIZE", Napi::Number::New(env, SM3_DIGEST_SIZE));
  exports.Set("SM3_HMAC_MIN_KEY_SIZE", Napi::Number::New(env, SM3_HMAC_MIN_KEY_SIZE));
  exports.Set("SM3_HMAC_MAX_KEY_SIZE", Napi::Number::New(env, SM3_HMAC_MAX_KEY_SIZE));
  exports.Set("SM3_HMAC_SIZE", Napi::Number::New(env, SM3_HMAC_SIZE));
  exports.Set("SM3_PBKDF2_MIN_ITER", Napi::Number::New(env, SM3_PBKDF2_MIN_ITER));
  exports.Set("SM3_PBKDF2_MAX_ITER", Napi::Number::New(env, SM3_PBKDF2_MAX_ITER));
  exports.Set("SM3_PBKDF2_MAX_SALT_SIZE", Napi::Number::New(env, SM3_PBKDF2_MAX_SALT_SIZE));
  exports.Set("SM3_PBKDF2_DEFAULT_SALT_SIZE", Napi::Number::New(env, SM3_PBKDF2_DEFAULT_SALT_SIZE));
  exports.Set("SM3_PBKDF2_MAX_KEY_SIZE", Napi::Number::New(env, SM3_PBKDF2_MAX_KEY_SIZE));
  exports.Set("SM4_KEY_SIZE", Napi::Number::New(env, SM4_KEY_SIZE));
  exports.Set("SM4_BLOCK_SIZE", Napi::Number::New(env, SM4_BLOCK_SIZE));
  exports.Set("SM4_CBC_IV_SIZE", Napi::Number::New(env, SM4_CBC_IV_SIZE));
  exports.Set("SM4_CTR_IV_SIZE", Napi::Number::New(env, SM4_CTR_IV_SIZE));
  exports.Set("SM4_GCM_MIN_IV_SIZE", Napi::Number::New(env, SM4_GCM_MIN_IV_SIZE));
  exports.Set("SM4_GCM_MAX_IV_SIZE", Napi::Number::New(env, SM4_GCM_MAX_IV_SIZE));
  exports.Set("SM4_GCM_DEFAULT_IV_SIZE", Napi::Number::New(env, SM4_GCM_DEFAULT_IV_SIZE));
  exports.Set("SM4_GCM_DEFAULT_TAG_SIZE", Napi::Number::New(env, SM4_GCM_DEFAULT_TAG_SIZE));
  exports.Set("SM4_GCM_MAX_TAG_SIZE", Napi::Number::New(env, SM4_GCM_MAX_TAG_SIZE));
  exports.Set("SM2_DEFAULT_ID", Napi::String::New(env, SM2_DEFAULT_ID));
  exports.Set("SM2_MAX_SIGNATURE_SIZE", Napi::Number::New(env, SM2_MAX_SIGNATURE_SIZE));
  exports.Set("SM2_MIN_PLAINTEXT_SIZE", Napi::Number::New(env, SM2_MIN_PLAINTEXT_SIZE));
  exports.Set("SM2_MAX_PLAINTEXT_SIZE", Napi::Number::New(env, SM2_MAX_PLAINTEXT_SIZE));
  exports.Set("SM2_MIN_CIPHERTEXT_SIZE", Napi::Number::New(env, SM2_MIN_CIPHERTEXT_SIZE));
  exports.Set("SM2_MAX_CIPHERTEXT_SIZE", Napi::Number::New(env, SM2_MAX_CIPHERTEXT_SIZE));
  exports.Set("SM9_MAX_ID_SIZE", Napi::Number::New(env, SM9_MAX_ID_SIZE));
  exports.Set("SM9_MAX_PLAINTEXT_SIZE", Napi::Number::New(env, SM9_MAX_PLAINTEXT_SIZE));
  exports.Set("SM9_MAX_CIPHERTEXT_SIZE", Napi::Number::New(env, SM9_MAX_CIPHERTEXT_SIZE));
  exports.Set("SM9_SIGNATURE_SIZE", Napi::Number::New(env, SM9_SIGNATURE_SIZE));
  exports.Set("ZUC_KEY_SIZE", Napi::Number::New(env, ZUC_KEY_SIZE));
  exports.Set("ZUC_IV_SIZE", Napi::Number::New(env, ZUC_IV_SIZE));
  exports.Set("GMSSL_NODEJS_VERSION", Napi::String::New(env, GMSSL_NODEJS_VERSION));

  return exports;
}

NODE_API_MODULE(gmssl_native, InitModule)
