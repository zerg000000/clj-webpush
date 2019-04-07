(ns webpush.vapid
  "Implementation of rfc8292 
   Voluntary Application Server Identification (VAPID) for Web Push"
  (:require 
   [clojure.spec.alpha :as s]
   [buddy.sign.jwt :as jwt]
   [buddy.core.codecs :as codecs] 
   [buddy.core.codecs.base64 :as base64]
   [webpush.keys :as wk])
  (:import [java.util Date]
           java.net.URL))

; fix uri checking
(s/def :webpush.vapid.claim/aud uri?)
(s/def :webpush.vapid.claim/exp int?)
(s/def :webpush.vapid.claim/sub uri?)

(s/def :webpush.vapid/claim
  (s/keys :req-un [:webpush.vapid.claim/aud
                   :webpush.vapid.claim/exp]
          :opt-un [:webpush.vapid.claim/sub]))

(defn origin [url-str]
  (let [url (URL. url-str)]
    (str (.getProtocol url) "://" (.getHost url))))

(defn crypto-key
  "an elliptic curve digital signature algorithm (ECDSA) 
   public key [FIPS186] in uncompressed form [X9.62]
   that is encoded using base64url encoding [RFC7515] ."
  [public-key]
  (-> public-key 
      wk/public-key->bytes 
      (base64/encode true) 
      codecs/bytes->str))

(defn authorization-token
  "The JWT MUST use a JSON Web Signature (JWS) [RFC7515] .  The signature
   MUST use ECDSA on the NIST P-256 curve [FIPS186] which is identified
   as ES256 [RFC7518] ."
  [private-key claims]
  (jwt/sign claims private-key {:alg :es256}))

(defn vapid-01-headers 
  [private-key public-key claims]
  {"Authorization" (str "WebPush " (authorization-token private-key claims))
   "Crypto-Key" (str "p256ecdsa=" (crypto-key public-key))})

(defn vapid-02-headers 
  [private-key public-key claims]
  {"Authorization" (str "vapid " 
                        "t=" (authorization-token private-key claims)
                        ", k=" (crypto-key public-key))})

(def vapid-headers vapid-02-headers)

(defn claims 
  [subscription subject]
  (merge
   {:aud (origin (:endpoint subscription))
    :exp (-> (Date.) (.getTime) (/ 1000) (+ (* 12 60)))
    :sub subject}))
