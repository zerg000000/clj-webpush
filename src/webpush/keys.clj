(ns webpush.keys
  (:require 
   [buddy.core.codecs.base64 :as base64])
  (:import 
   java.security.KeyPairGenerator
   java.security.Security
   java.security.PublicKey
   java.security.KeyPair
   java.security.KeyFactory
   org.bouncycastle.jce.ECNamedCurveTable
   org.bouncycastle.jce.interfaces.ECPublicKey
   org.bouncycastle.jce.spec.ECPublicKeySpec
   org.bouncycastle.jce.provider.BouncyCastleProvider))

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

(defn ^KeyPair new-keypair
  "generate prime256v1 keypair"
  []
  (let [param-spec (ECNamedCurveTable/getParameterSpec "prime256v1")
        keypair-generator (KeyPairGenerator/getInstance "ECDH" "BC")]
    (.initialize keypair-generator param-spec)
    (.generateKeyPair keypair-generator)))

(defn keypair->public-key 
  [^KeyPair keypair]
  (.getPublic keypair))

(defn keypair->private-key
  [^KeyPair keypair]
  (.getPrivate keypair))

(defn ^PublicKey str->public-key
  "convert base64 string to prime256v1 public key"
  [^String pub-key-str]
  (let [decoded (base64/decode pub-key-str)
        key-factory (KeyFactory/getInstance "ECDH" "BC")
        param-spec (ECNamedCurveTable/getParameterSpec "prime256v1")
        point (-> param-spec (.getCurve) (.decodePoint decoded))
        pub-spec (ECPublicKeySpec. point param-spec)]
    (.generatePublic key-factory pub-spec)))

(defn public-key->bytes
  "an elliptic curve digital signature algorithm (ECDSA) public key 
   [FIPS186] in uncompressed form [X9.62]"
  [^ECPublicKey public-key]
  (-> public-key
      .getQ
      (.getEncoded false)))