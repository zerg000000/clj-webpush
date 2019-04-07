(ns webpush.ece
  "This is an implementation of RFC 8291"
  (:require 
   [buddy.core.kdf :as kdf]
   [buddy.core.bytes :as bytes]
   [buddy.core.codecs :as codecs]
   [buddy.core.crypto :as crypto])
  (:import java.nio.ByteBuffer
           javax.crypto.KeyAgreement))

(defn int->bytes
  [input size]
  (let [buffer (ByteBuffer/allocate size)]
    (.putInt buffer input)
    (.array buffer)))

(defn hkdf-expand 
  [secret salt info length]
  (let [hkdf (kdf/engine {:alg :hkdf+sha256
                          :key secret
                          :salt salt
                          :info info})]
    (kdf/get-bytes hkdf length)))

(defn agreement-secret 
  [pri-key p256dh]
  (let [key-agreement (KeyAgreement/getInstance "ECDH")]
    (.init key-agreement pri-key)
    (.doPhase key-agreement p256dh true)
    (.generateSecret key-agreement)))

(defn webpush-secret 
  [pri-key pub-key p256dh auth]
  (let [secret (agreement-secret pri-key p256dh)
        info (bytes/concat (codecs/str->bytes "WebPush: info\0")
                           (-> p256dh .getQ (.getEncoded false))
                           (-> pub-key .getQ (.getEncoded false)))]
    (hkdf-expand secret auth info 32)))

(defn encrypt
  [payload salt secret]
  (let [key (hkdf-expand secret salt
                         (codecs/str->bytes "Content-Encoding: aes128gcm\0")
                         16)
        nonce (hkdf-expand secret salt
                           (codecs/str->bytes "Content-Encoding: nonce\0")
                           12)
        padding (byte-array [(byte 2)])
        encrypted (crypto/encrypt (bytes/concat payload padding)
                                  key nonce
                                  {:algorithm :aes128-gcm})]
    (bytes/concat
     salt
     (int->bytes 4096 4)
     (byte-array 1)
     (byte-array 0)
     encrypted)))