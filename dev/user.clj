(require '[webpush.core :as webpush])
(require '[org.httpkit.client :as http])
(require '[buddy.core.keys :as keys])
(import 'java.io.ByteArrayInputStream)

(def req
  (webpush/->rfc8291-request "Hello"
                           {:vapid/private-key (keys/private-key "vapid_private.pem")
                            :vapid/public-key (keys/public-key "vapid_public.pem")
                            :claim/subject "example@example.com"}
                           {:endpoint "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABag_RdNj4gsfqMCJp5GZvPyoBtWor5gxS_CW9HjJkoD-2MjqaxPS7g6TcuS52I1E3yPn0NQ93PSIf7E-QWs5MfvPhUAYGeCLuqY-eniKI0D-gE0szFS0GueTq--EFyYbYB0lywdyONFjRnmSXOrX9jEXqoAgtlu1DP6ruOmxnH8Jhk7aw"
                            :keys {:p256dh "BPZpmSlIvI6m5hBYr69v0e40P2y1mQjA4toxYIPDM1lUlZwvmYGeDIUR-LaDBmPP4wFAUzRwCw2bHqZsqOKV2jk"
                                   :auth "pOsX0WXpVKvcFqFSeSkpJQ"}}))

@(http/request (-> (update req :body #(ByteArrayInputStream. %))
                   (update :url #(clojure.string/replace % "fcm/send" "wp"))))