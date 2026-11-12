(ns keyinfra.core
  (:import [goog.string format])
  (:require-macros [cljs.core.async.macros :refer [go go-loop]])
  (:require
    [cljs.core.async :refer [put! chan <! >! timeout close! onto-chan]]
    [clojure.string :as string]
    [replicant.dom :as r]))

(defn csr! [id]
  (let [ch (chan)]
    (-> (format "http://localhost:5000/csr/%s" id)
        (js/fetch #js{:method "POST"})
        (.then #(.text %))
        (.then #(put! ch %))
        (.catch #(js/console.error (.-message %)))
        (.finally #(close! ch)))
    ch))

(defn crt! [id chain]
  (let [ch (chan)]
    (-> (format "http://localhost:5000/crt/%s" id)
        (js/fetch #js{:method "POST" :body (js/JSON.stringify (clj->js chain))
                      :headers #js{"content-type" "application/json"}})
        (.then #(.text %))
        (.then #(put! ch %))
        (.catch #(js/console.error (.-message %)))
        (.finally #(close! ch)))
    ch))

(comment

  (def foo (random-uuid))
  (go (def resp1 (<! (csr! foo))))
  
  (go (def resp2 (<! (crt! foo []))))

;; // 4. The certificate authority parses the request and checks its signature
;; const received = pkijs.CertificationRequest.fromBER(der);
;; const signatureValid = await received.verify();
;; console.log("Signature valid:", signatureValid);
;; if (!signatureValid) {
;;   throw new Error("The request signature is invalid");
;; }
  
  )


;; (declare refresh)

;; (defonce state
;;   (doto (atom {:n 0})
;;     (add-watch :render (fn [k r o n] (refresh n)))))

;; (r/set-dispatch!
;;   (fn [replicant-data handler-data]
;;     (swap! state update :n inc)))

;; (defn refresh [s]
;;   (r/render (js/document.getElementById "app")
;;     [:div.container
;;      [:main
;;       [:h2 "Replicant SVG Demo"]
;;       [:p (format "Just wrote some documentation for Replicant. %d" (get s :n 0))]
;;       [:input {:type "button"
;;                :value "inc"
;;                :on {:click [:foo]}}]
;;     [:svg {:height 150 :width 500 :xmlns "http://www.w3.org/2000/svg" :viewBox "0 0 200 200"}
;;       [:ellipse {:cx "240"
;;                  :cy "100"
;;                  :rx "220"
;;                  :ry (-> s :n (* 10))
;;                  :fill "purple"}]
;;       [:ellipse {:cx "220"
;;                  :cy "70"
;;                  :rx "190"
;;                  :ry "20"
;;                  :fill "lime"}]
;;       [:ellipse {:cx "210"
;;                  :cy "45"
;;                  :rx "170"
;;                  :ry "15"
;;                  :fill "yellow"}]]
;;       [:p.opacity-50
;;        "Posted 18th September 2025"]]]))

;; (defn -main [& args]
;;   (refresh @state))
