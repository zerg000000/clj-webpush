(ns webpush.vapid-test
  (:require 
   [clojure.test :refer :all]
   [buddy.core.keys :as keys]
   [webpush.vapid :as vapid]))

(deftest vapid-test
  (let [pkey (keys/private-key "vapid_private.pem")
        pubkey (keys/public-key "vapid_public.pem")]
    (testing "Crypto-Key"
      (is (= (get (vapid/vapid-01-headers pkey pubkey (vapid/claims {:endpoint "http://example.com"}
                                                                    {:sub "mailto:admin @example.com"}))
                  "Crypto-Key")
             (str "p256ecdsa="
                  "BBCcCWavxjfIyW6NRhqclO9IZj9oW1gFKUBSgwcigfNc"
                  "pXSfRk5JQTOcahMLjzO1bkHMoiw4b6L7YTyF8foLEEU"))))
    (testing "Authorization"
      (is (= "WebPush eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJleHAiOjE1NTE1MzkzMDY4NDAsInN1YiI6Im1haWx0bzphZG1pbiBAZXhhbXBsZS5jb20ifQ.Dm3oa05TkRZY28T-8t-aI6rOd_wa79hE-caMvQStpmCjKPNjP03BD-akB3aLQh1fILBu8CE6zYfIor7Mgqqmhw"
             (get (vapid/vapid-01-headers pkey pubkey (vapid/claims {:endpoint "http://example.com"}
                                                                    {:sub "mailto:admin @example.com"}))
                  "Authorization"))))))
