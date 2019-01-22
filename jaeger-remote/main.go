package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaeger "github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
	"github.com/uber/jaeger-lib/metrics"
	"go.uber.org/zap"
)

var endpointRequest = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "endpoint_request",
		Help: "Request endpoint count",
	},
	[]string{"http_code", "endpoint"},
)

var traceRecord = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "trace_recorded",
		Help: "Count of successfull recorded traces",
	},
	[]string{"origin"},
)

var logger, _ = zap.NewDevelopment()
var sugar = logger.Sugar()

var traceEndpointName = "/trace"

var listenIP string
var listenPort int

var jaegerLocalAgentHostPort, jaegerServiceName string

func main() {
	defer logger.Sync() // flushes buffer, if any

	sugar.Infof("Starting Jaeger Remote Tracer")

	flag.StringVar(&listenIP, "listen-address", "0.0.0.0", "REST API server listen ip address")
	flag.IntVar(&listenPort, "listen-port", 3000, "REST API server listen port")
	flag.StringVar(&jaegerServiceName, "jaeger-service-name", "dummy", "Jaeger hostname for communicating with agent via UDP")
	flag.StringVar(&jaegerLocalAgentHostPort, "jaeger-agent-host-port", "localhost:6831", "Jaeger hostname and port for communicating with agent via UDP")
	flag.Parse()

	sugar.Infof("Initialiazing Jaeger....")
	sugar.Infof("Service Name: %s", jaegerServiceName)
	sugar.Infof("LocalAgentHostPort: %s", jaegerLocalAgentHostPort)

	if jaegerServiceName != "" {

		sugar.Infof("Jaeger Service Name provided. Setting up a Global Tracer for service '%s'", jaegerServiceName)
		cfg := &config.Configuration{
			ServiceName: jaegerServiceName,
			Sampler: &config.SamplerConfig{
				Type:  jaeger.SamplerTypeConst,
				Param: 1,
			},
			Reporter: &config.ReporterConfig{
				LogSpans:           true,
				LocalAgentHostPort: jaegerLocalAgentHostPort,
			},
		}
		tracer, closer, err := cfg.NewTracer(config.Logger(jaegerlog.StdLogger), config.Metrics(metrics.NullFactory))
		if err != nil {
			panic(fmt.Sprintf("ERROR: cannot init Jaeger: %v\n", err))
		}
		opentracing.SetGlobalTracer(tracer)
		defer closer.Close()

	}

	prometheus.MustRegister(endpointRequest)
	prometheus.MustRegister(traceRecord)

	router := mux.NewRouter()
	router.HandleFunc(traceEndpointName, handleCreateTrace).Methods("POST")
	router.Handle("/metrics", promhttp.Handler())
	listen := fmt.Sprintf("%s:%d", listenIP, listenPort)
	sugar.Infof("Listening at %s", listen)
	err2 := http.ListenAndServe(listen, router)
	if err2 != nil {
		sugar.Errorf("Error starting HTTP Server. Details: %s", err2)
	}

}

func handleCreateTrace(w http.ResponseWriter, r *http.Request) {
	sugar.Debugf("Parsing input json to map")

	originStr := r.Header.Get("Trace-Origin")
	traceRecord.WithLabelValues(originStr).Inc()

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sugar.Warnf("Error reading request body. Error details: %s", err)
		endpointRequest.WithLabelValues("500", traceEndpointName).Inc()
		http.Error(w, "Error reading request body", 500)
		return
	}

	jsonInput := make(map[string]interface{})
	if len(bodyBytes) > 0 {
		err = json.Unmarshal(bodyBytes, &jsonInput)
		if err != nil {
			sugar.Warnf("Error parsing json body to map. Error details: %s", err)
			endpointRequest.WithLabelValues("500", traceEndpointName).Inc()
			http.Error(w, "Invalid input JSON. Error: "+err.Error(), 500)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	var context = ""
	if jsonInput["context"] != nil {
		context = jsonInput["context"].(string)
	}
	var tags = make(map[string]interface{})
	if jsonInput["context"] != nil {
		tags = jsonInput["tags"].(map[string]interface{})
	}
	output := Trace(jsonInput["name"].(string), context, tags)
	outBytes, err := json.Marshal(output)
	if err != nil {
		sugar.Warnf("Error converting tracing data to JSON. Error details: %s", err)
		endpointRequest.WithLabelValues("500", traceEndpointName).Inc()
		http.Error(w, "Invalid trace data received. Error: "+err.Error(), 500)
		return
	}

	_, err = w.Write(outBytes)
	if err != nil {
		sugar.Warnf("Error writing response. Error details: %s", err)
		endpointRequest.WithLabelValues("500", traceEndpointName).Inc()
		http.Error(w, "Error writing response. Error: "+err.Error(), 500)
		return
	}
}

// Trace record the trace with the values received
func Trace(name string, context string, tags map[string]interface{}) map[string]interface{} {
	output := make(map[string]interface{})
	tracer := opentracing.GlobalTracer()

	span := tracer.StartSpan(name)
	println(name)
	span.Finish()

	return output
}
