package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/opentracing/opentracing-go"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaeger "github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
	jaegerProm "github.com/uber/jaeger-lib/metrics/prometheus"
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

var listenIP string
var listenPort int
var jaegerLocalAgentHostPort, jaegerServiceName string

var spanStartAndFinishEndpointName = "/trace"
var spanStartEndpointName = "/trace/start"
var spanFinishEndpointName = "/trace/finish"

var pendingSpans = make(map[string]opentracing.Span)
var pendingCloser = make(map[string]io.Closer)

var traceConfig config.Configuration
var metricsFactory *jaegerProm.Factory

func main() {
	defer logger.Sync() // flushes buffer, if any

	sugar.Infof("Starting Jaeger Remote Tracer")

	flag.StringVar(&listenIP, "listen-address", "0.0.0.0", "REST API server listen ip address")
	flag.IntVar(&listenPort, "listen-port", 3000, "REST API server listen port")
	flag.StringVar(&jaegerServiceName, "jaeger-service-name", "dummy", "Jaeger hostname for communicating with agent via UDP")
	flag.StringVar(&jaegerLocalAgentHostPort, "jaeger-agent-host-port", "localhost:6831", "Jaeger hostname and port for communicating with agent via UDP")
	flag.Parse()

	sugar.Infof("Initialiazing Jaeger....")
	sugar.Infof("Global Service Name: %s", jaegerServiceName)
	sugar.Infof("LocalAgentHostPort: %s", jaegerLocalAgentHostPort)

	traceConfig = config.Configuration{
		Sampler: &config.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
		},
		Reporter: &config.ReporterConfig{
			LogSpans:           true,
			LocalAgentHostPort: jaegerLocalAgentHostPort,
		},
	}

	metricsFactory = jaegerProm.New()

	prometheus.MustRegister(endpointRequest)
	prometheus.MustRegister(traceRecord)

	router := mux.NewRouter()
	router.HandleFunc(spanStartAndFinishEndpointName, handleStartAndFinishTrace).Methods("POST")
	router.HandleFunc(spanStartEndpointName, handleStartSpan).Methods("POST")
	router.HandleFunc(spanFinishEndpointName, handleFinishSpan).Methods("POST")
	router.Handle("/metrics", promhttp.Handler())

	listen := fmt.Sprintf("%s:%d", listenIP, listenPort)
	sugar.Infof("Listening at %s", listen)
	err2 := http.ListenAndServe(listen, router)
	if err2 != nil {
		sugar.Errorf("Error starting HTTP Server. Details: %s", err2)
	}

}

func handleBaseSpanCreation(endpointName string, w http.ResponseWriter, r *http.Request, traceFunction func(string, string, map[string]string, map[string]interface{}) map[string]string) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sugar.Warnf("Error reading request body. Error details: %s", err)
		endpointRequest.WithLabelValues("500", endpointName).Inc()
		http.Error(w, "Error reading request body", 500)
		return
	}

	jsonInput := make(map[string]interface{})
	if len(bodyBytes) > 0 {
		err = json.Unmarshal(bodyBytes, &jsonInput)
		if err != nil {
			sugar.Warnf("Error parsing json body to map. Error details: %s", err)
			endpointRequest.WithLabelValues("500", endpointName).Inc()
			http.Error(w, "Invalid input JSON. Error: "+err.Error(), 500)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	var context map[string]interface{}
	if jsonInput["context"] != nil {
		context = jsonInput["context"].(map[string]interface{})
	}
	var tags = make(map[string]interface{})
	if jsonInput["tags"] != nil {
		tags = jsonInput["tags"].(map[string]interface{})
	}

	var serviceName = jaegerServiceName
	if serviceName == "" || jsonInput["serviceName"].(string) != "" { //if the serviceName is provided, it will override the global one
		serviceName = jsonInput["serviceName"].(string)
	}

	// count traces by service name
	traceRecord.WithLabelValues(serviceName).Inc()

	contextTrace := make(map[string]string)
	for key, value := range context {
		contextTrace[key] = value.(string)
	}

	//invoke the trace function
	output := traceFunction(serviceName, jsonInput["spanName"].(string), contextTrace, tags)
	outBytes, err := json.Marshal(output)

	if err != nil {
		sugar.Warnf("Error converting tracing data to JSON. Error details: %s", err)
		endpointRequest.WithLabelValues("500", endpointName).Inc()
		http.Error(w, "Invalid trace data received. Error: "+err.Error(), 500)
		return
	}

	_, err = w.Write(outBytes)
	if err != nil {
		sugar.Warnf("Error writing response. Error details: %s", err)
		endpointRequest.WithLabelValues("500", endpointName).Inc()
		http.Error(w, "Error writing response. Error: "+err.Error(), 500)
		return
	}

	endpointRequest.WithLabelValues("200", endpointName).Inc()
}

func handleStartAndFinishTrace(w http.ResponseWriter, r *http.Request) {
	handleBaseSpanCreation(spanStartAndFinishEndpointName, w, r, StartAndFinishTrace)
}

func handleStartSpan(w http.ResponseWriter, r *http.Request) {
	handleBaseSpanCreation(spanStartAndFinishEndpointName, w, r, StartTrace)
}

func handleFinishSpan(w http.ResponseWriter, r *http.Request) {
	handleBaseSpanCreation(spanStartAndFinishEndpointName, w, r, FinishTrace)
}

// StartAndFinishTrace record the trace with the values received and returns its context
func StartAndFinishTrace(serviceName string, spanName string, context map[string]string, tags map[string]interface{}) map[string]string {
	output := make(map[string]string)

	tracer, closer, err := traceConfig.New(serviceName, config.Logger(jaegerlog.StdLogger), config.Metrics(metricsFactory))
	if err != nil {
		panic(fmt.Sprintf("ERROR: cannot init Jaeger: %v\n", err))
	}
	defer closer.Close()

	var span opentracing.Span
	if context != nil {
		spanCtx, err := tracer.Extract(opentracing.TextMap, opentracing.TextMapCarrier(context))
		if err == nil {
			span = tracer.StartSpan(spanName, opentracing.ChildOf(spanCtx))
		} else { // if there's a error extracting, trace, but put a tag pointing the error
			span = tracer.StartSpan(spanName)
			span.SetTag("trace-fallback", "error-retrieving-the-context")
		}
	} else {
		span = tracer.StartSpan(spanName)
	}

	span.Finish()

	// return the Context in the response so the client can forward it to keep the trace chain
	span.Tracer().Inject(span.Context(), opentracing.TextMap, opentracing.TextMapCarrier(output))

	return output
}

// StartTrace starts the trace with the values received and returns its context
func StartTrace(serviceName string, spanName string, context map[string]string, tags map[string]interface{}) map[string]string {
	output := make(map[string]string)

	tracer, closer, err := traceConfig.New(serviceName, config.Logger(jaegerlog.StdLogger), config.Metrics(metricsFactory))
	if err != nil {
		panic(fmt.Sprintf("ERROR: cannot init Jaeger: %v\n", err))
	}

	var span opentracing.Span
	if context != nil {
		spanCtx, err := tracer.Extract(opentracing.TextMap, opentracing.TextMapCarrier(context))
		if err == nil {
			span = tracer.StartSpan(spanName, opentracing.ChildOf(spanCtx))
		} else { // if there's a error extracting, trace, but put a tag pointing the error
			span = tracer.StartSpan(spanName)
			span.SetTag("trace-fallback", "error-retrieving-the-context")
		}
	} else {
		span = tracer.StartSpan(spanName)
	}

	uuid1, err := uuid.NewUUID()
	uuid4, err := uuid.NewRandom()
	traceRequestID := uuid1.String() + "<>" + uuid4.String()
	println(traceRequestID)
	pendingSpans[traceRequestID] = span
	pendingCloser[traceRequestID] = closer
	output["traceRequestID"] = traceRequestID

	// return the Context in the response so the client can forward it to keep the trace chain
	span.Tracer().Inject(span.Context(), opentracing.TextMap, opentracing.TextMapCarrier(output))

	return output
}

// FinishTrace starts the trace with the values received and returns its context
func FinishTrace(serviceName string, spanName string, context map[string]string, tags map[string]interface{}) map[string]string {
	output := make(map[string]string)

	span := pendingSpans[context["traceRequestID"]]
	closer := pendingCloser[context["traceRequestID"]]
	defer closer.Close()
	span.Finish()
	// return the Context in the response so the client can forward it to keep the trace chain
	span.Tracer().Inject(span.Context(), opentracing.TextMap, opentracing.TextMapCarrier(output))

	return output
}
