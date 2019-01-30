package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/google/uuid"
	"github.com/gorilla/handlers"
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
	router.HandleFunc(spanStartEndpointName, handleStartSpan).Methods("POST")
	router.HandleFunc(spanFinishEndpointName, handleFinishSpan).Methods("POST")
	router.Handle("/metrics", promhttp.Handler())

	listen := fmt.Sprintf("%s:%d", listenIP, listenPort)
	sugar.Infof("Listening at %s", listen)

	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	err2 := http.ListenAndServe(listen, handlers.CORS(originsOk, headersOk, methodsOk)(router))
	if err2 != nil {
		sugar.Errorf("Error starting HTTP Server. Details: %s", err2)
	}

}

func handleBaseSpanCreation(endpointName string, w http.ResponseWriter, r *http.Request, traceFunction func(string, string, map[string]string, map[string]interface{}) (map[string]string, error)) {
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

	var spanName = ""
	if jsonInput["spanName"] != nil {
		spanName = jsonInput["spanName"].(string)
	}

	var context map[string]interface{}
	if jsonInput["context"] != nil {
		context = jsonInput["context"].(map[string]interface{})
	}
	var tags = make(map[string]interface{})
	if jsonInput["tags"] != nil {
		tags = jsonInput["tags"].(map[string]interface{})
	}

	var serviceName = jaegerServiceName
	if serviceName == "" || (jsonInput["serviceName"] != nil && jsonInput["serviceName"].(string) != "") { //if the serviceName is provided, it will override the global one
		serviceName = jsonInput["serviceName"].(string)
	}

	// count traces by service name
	traceRecord.WithLabelValues(serviceName).Inc()

	contextTrace := make(map[string]string)
	for key, value := range context {
		contextTrace[key] = value.(string)
	}

	//invoke the trace function
	output, err := traceFunction(serviceName, spanName, contextTrace, tags)
	if err != nil {
		endpointRequest.WithLabelValues("500", endpointName).Inc()
		http.Error(w, "Invalid trace data received. Error: "+err.Error(), 500)
		return
	}

	outBytes, err := json.Marshal(output)

	if err != nil {
		sugar.Warnf("Error converting tracing data to JSON. Error details: %s", err)
		endpointRequest.WithLabelValues("500", endpointName).Inc()
		http.Error(w, "Error writing response. Error: "+err.Error(), 500)
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

func handleStartSpan(w http.ResponseWriter, r *http.Request) {
	sugar.Infof("START HTTP ENDPOINT")
	handleBaseSpanCreation(spanStartEndpointName, w, r, StartTrace)
}

func handleFinishSpan(w http.ResponseWriter, r *http.Request) {
	sugar.Infof("FINISH HTTP ENDPOINT")
	handleBaseSpanCreation(spanFinishEndpointName, w, r, FinishTrace)
}

// StartTrace starts the trace with the values received and returns its context
func StartTrace(serviceName string, spanName string, context map[string]string, tags map[string]interface{}) (map[string]string, error) {

	if serviceName == "" {
		return nil, errors.New("`serviceName` attribute is a required field on the request. Please check your request body")
	}

	if spanName == "" {
		return nil, errors.New("`spanName` attribute is a required field on the request. Please check your request body")
	}

	sugar.Infof("TAGS %s", tags)

	output := make(map[string]string)

	tracer, closer, err := traceConfig.New(serviceName, config.Logger(jaegerlog.StdLogger), config.Metrics(metricsFactory))
	opentracing.SetGlobalTracer(tracer)
	if err != nil {
		panic(fmt.Sprintf("ERROR: cannot init Jaeger: %v\n", err))
	}

	var span opentracing.Span
	if context != nil && len(context) > 0 {
		spanCtx, err := tracer.Extract(opentracing.TextMap, opentracing.TextMapCarrier(context))
		if err == nil {
			span = tracer.StartSpan(spanName, opentracing.ChildOf(spanCtx), opentracing.Tags(tags))
		} else { // if there's a error extracting, trace, but put a tag pointing the error
			span = tracer.StartSpan(spanName, opentracing.Tags(tags))
			span.SetTag("trace-fallback", "error-retrieving-the-context-start-async")
		}
	} else {
		span = tracer.StartSpan(spanName, opentracing.Tags(tags))
	}

	sugar.Infof("Start TRACE: %s ---- %s => %s", serviceName, span, time.Now().Unix())
	uuid1, err := uuid.NewUUID()
	uuid4, err := uuid.NewRandom()
	traceRequestID := uuid1.String() + "<>" + uuid4.String()
	println(traceRequestID)
	pendingSpans[traceRequestID] = span
	pendingCloser[traceRequestID] = closer
	span.Tracer().Inject(span.Context(), opentracing.TextMap, opentracing.TextMapCarrier(output))
	output["traceRequestID"] = traceRequestID

	return output, nil
}

// FinishTrace starts the trace with the values received and returns its context
func FinishTrace(serviceName string, spanName string, context map[string]string, tags map[string]interface{}) (map[string]string, error) {
	if context == nil {
		return nil, errors.New("`context` attribute is a required field on the request. It must have a `traceID` field with the correlated started trace")
	}

	if val, ok := context["traceRequestID"]; !ok || val == "" { //check whether the value was not present in the request body
		return nil, errors.New("`context.traceRequestID` attribute is a required field on the request. Please check your request body to ensure it is like: { context: { traceRequestID: '<TRACE_ID_RECEIVED_AT_TRACE_START>' } }")
	}

	output := make(map[string]string)

	span := pendingSpans[context["traceRequestID"]]
	sugar.Infof("Finish TRACE: %s => %s", span, time.Now().Unix())
	if span == nil {
		return nil, fmt.Errorf("Span with traceRequestID=%s not found. Maybe the remote-tracer server has been restarted or you hit a different instance at start and finish", context["traceRequestID"])
	}
	span.Finish()

	closer := pendingCloser[context["traceRequestID"]]
	defer closer.Close()
	// return the Context in the response so the client can forward it to keep the trace chain

	return output, nil
}
