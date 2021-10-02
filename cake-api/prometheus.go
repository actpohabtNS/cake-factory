package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reqBuckets      = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
	registeredUsers = promauto.NewCounter(prometheus.CounterOpts{
		Name: "number_of_registered_users",
		Help: "The total number of registered users.",
	})
	cakesGiven = promauto.NewCounter(prometheus.CounterOpts{
		Name: "number_of_cakes_given",
		Help: "The total number of given cakes.",
	})
	requestRecords = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "api_request_record_seconds",
		Help:    "Histogram of response time for handler in seconds.",
		Buckets: reqBuckets,
	}, []string{"path"})
)

func startProm() {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}
