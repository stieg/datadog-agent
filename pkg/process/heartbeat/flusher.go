package heartbeat

import (
	"fmt"
	"net/http"
	"time"

	"github.com/DataDog/datadog-agent/pkg/forwarder"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-go/statsd"
)

const metricName = "datadog.system_probe.agent.%s"

type flusher interface {
	Flush(modules []string, now time.Time)
	Stop()
}

type flusherImpl struct {
	forwarder forwarder.Forwarder
	fallback  flusher
	tags      []string
}

var _ flusher = &flusherImpl{}

func newFlusher(opts Options) flusher {
	// Instantiate forwarder responsible for sending hearbeat metrics to the API
	fwdOpts := forwarder.NewOptions(opts.KeysPerDomain)
	fwdOpts.DisableAPIKeyChecking = true
	heartbeatForwarder := forwarder.NewDefaultForwarder(fwdOpts)
	heartbeatForwarder.Start()

	var tags []string
	if opts.TagVersion != "" {
		tags = append(tags, fmt.Sprintf("version:%s", opts.TagVersion))
	}
	if opts.TagRevision != "" {
		tags = append(tags, fmt.Sprintf("version:%s", opts.TagRevision))
	}

	return &flusherImpl{
		forwarder: heartbeatForwarder,
		fallback:  &statsdFlusher{client: opts.StatsdClient, tags: tags},
		tags:      tags,
	}
}

// Flush heartbeats metrics for each system-probe module to Datadog.  We first
// attempt to flush it via the Metrics API. In case of failures we fallback to
// `statsd`.
func (f *flusherImpl) Flush(modules []string, now time.Time) {
	if len(modules) == 0 {
		return
	}

	heartbeats, err := f.jsonPayload(modules, now)
	if err != nil {
		log.Errorf("error marshaling heartbeats payload: %s", err)
		return
	}

	payload := forwarder.Payloads{&heartbeats}
	if err := f.forwarder.SubmitSeries(payload, http.Header{}); err != nil {
		log.Errorf("could not flush heartbeats to API: %s. trying statsd...", err)
		f.fallback.Flush(modules, now)
	}
}

// Stop forwarder
func (f *flusherImpl) Stop() {
	f.forwarder.Stop()
}

func (f *flusherImpl) jsonPayload(modules []string, now time.Time) ([]byte, error) {
	if len(modules) == 0 {
		return nil, nil
	}

	ts := float64(now.Unix())
	heartbeats := make(metrics.Series, 0, len(modules))
	for _, moduleName := range modules {
		serie := &metrics.Serie{
			Name: fmt.Sprintf(metricName, moduleName),
			Tags: f.tags,
			Points: []metrics.Point{
				{
					Ts:    ts,
					Value: float64(1),
				},
			},
		}
		heartbeats = append(heartbeats, serie)
	}

	return heartbeats.MarshalJSON()
}

type statsdFlusher struct {
	client statsd.ClientInterface
	tags   []string
}

var _ flusher = &statsdFlusher{}

// Flush heartbeats via statsd
func (f *statsdFlusher) Flush(modules []string, _ time.Time) {
	for _, moduleName := range modules {
		f.client.Gauge(fmt.Sprintf(metricName, moduleName), 1, f.tags, 1) //nolint:errcheck
	}
}

// Stop flusher
func (f *statsdFlusher) Stop() {}
