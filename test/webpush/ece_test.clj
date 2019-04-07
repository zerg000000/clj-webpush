(ns webpush.ece-test
  (:require
   [clojure.test :refer :all]
   [buddy.core.codecs.base64 :as base64]
   [buddy.core.codecs :as codecs]
   [webpush.ece :as ece]))

(deftest basic-tests
  (testing "no salt and key"
    (is (= "AAAAAAAAAAAAAAAAAAAAAAAAEAAAMpsi6NfZUkOdJI96XyX0tavLqyIdiw"
           (-> (ece/encrypt (codecs/str->bytes "Hello")
                            (byte-array 16)
                            (byte-array 16))
               (base64/encode true)
               (codecs/bytes->str)))))
  (testing "simple encryption"
    (is (= "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg"
           (-> (ece/encrypt (codecs/str->bytes "I am the walrus")
                            (-> (codecs/str->bytes "I1BsxtFttlv3u_Oo94xnmw")
                                (base64/decode))
                            (-> (codecs/str->bytes "yqdlZ-tYemfogSmv7Ws5PQ")
                                (base64/decode)))
               (base64/encode true)
               (codecs/bytes->str))))))