(ns webpush.core
  (:require
   [buddy.core.nonce :as nonce]
   [buddy.core.keys :as keys]
   [buddy.core.bytes :as bytes]
   [buddy.core.codecs :as codecs]
   [buddy.core.codecs.base64 :as base64]
   [webpush.keys :as wk]
   [webpush.ece :as ece]
   [webpush.vapid :as vapid]))

(defn encrypt
  [text p256dh auth]
  (let [salt (nonce/random-nonce 16)
        keypair (wk/new-keypair)
        secret (ece/webpush-secret
                (wk/keypair->private-key keypair)
                (wk/keypair->public-key keypair)
                (wk/str->public-key p256dh)
                (base64/decode auth))]
    {:salt salt
     :public-key (-> keypair wk/keypair->public-key wk/public-key->bytes)
     :encrypted (ece/encrypt (codecs/str->bytes text) salt secret)}))

(defn ->rfc8291-request
  "WebPush Encryption
   https://tools.ietf.org/html/rfc8291"
  [message server-config subscription]
  (let [headers (vapid/vapid-02-headers (:vapid/private-key server-config) (:vapid/public-key server-config)
                                        (vapid/claims subscription (:claim/subject server-config)))
        encrypted (encrypt message (get-in subscription [:keys :p256dh]) (get-in subscription [:keys :auth]))]
    {:headers (merge {"Content-Type" "application/octet-stream"
                      "Content-Encoding" "aes128gcm"
                      "TTL" 2419200} headers)
     :url (let [url (:endpoint subscription)]
            (if (clojure.string/starts-with? url "https://fcm.googleapis.com")
              (clojure.string/replace url "fcm/send" "wp")
              url))
     :method :post
     :body (:encrypted encrypted)}))